package events_test

import (
	"sync"
	"testing"
	"time"

	"github.com/silvance/golantern/internal/events"
)

func TestSubscribePublishUnsubscribe(t *testing.T) {
	b := events.NewBus(nil)
	ch := b.Subscribe("r1")
	if b.SubscriberCount("r1") != 1 {
		t.Fatalf("subscriber count = %d, want 1", b.SubscriberCount("r1"))
	}
	delivered := b.Publish(events.Event{RunID: "r1", Kind: events.KindRunStarted})
	if delivered != 1 {
		t.Fatalf("delivered=%d, want 1", delivered)
	}
	select {
	case ev := <-ch:
		if ev.Kind != events.KindRunStarted {
			t.Fatalf("got %v", ev)
		}
		if ev.Timestamp.IsZero() {
			t.Fatal("Publish should stamp Timestamp")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	b.Unsubscribe("r1", ch)
	if b.SubscriberCount("r1") != 0 {
		t.Fatalf("subscriber count after unsubscribe = %d", b.SubscriberCount("r1"))
	}
	// Channel closed; range exits without reading anything more.
	if _, ok := <-ch; ok {
		t.Fatal("Unsubscribe must close the channel")
	}
}

func TestPublishWithNoSubscribersIsCheap(t *testing.T) {
	b := events.NewBus(nil)
	if got := b.Publish(events.Event{RunID: "nobody", Kind: "x"}); got != 0 {
		t.Fatalf("delivered=%d, want 0", got)
	}
}

func TestFanOutToMultipleSubscribers(t *testing.T) {
	b := events.NewBus(nil)
	a := b.Subscribe("r1")
	c := b.Subscribe("r1")
	if got := b.Publish(events.Event{RunID: "r1", Kind: "x"}); got != 2 {
		t.Fatalf("delivered=%d, want 2", got)
	}
	for _, ch := range []chan events.Event{a, c} {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("timeout on subscriber")
		}
	}
}

func TestPublishDropsOnFullSubscriber(t *testing.T) {
	b := events.NewBus(nil)
	ch := b.Subscribe("r1")
	// Fill the buffer.
	for i := 0; i < events.QueueSize; i++ {
		b.Publish(events.Event{RunID: "r1", Kind: "x"})
	}
	// Next publish must drop, not block. Run it in a goroutine and
	// race it against a short timeout — if Publish blocks, the test
	// fails fast.
	done := make(chan int, 1)
	go func() {
		done <- b.Publish(events.Event{RunID: "r1", Kind: "y"})
	}()
	select {
	case got := <-done:
		if got != 0 {
			t.Fatalf("delivered=%d, want 0 (full subscriber should drop)", got)
		}
	case <-time.After(time.Second):
		t.Fatal("Publish blocked on a full subscriber")
	}
	// Drain so the goroutine that already filled the channel cleans up.
	for i := 0; i < events.QueueSize; i++ {
		<-ch
	}
}

func TestSubscribersAreIsolatedByRunID(t *testing.T) {
	b := events.NewBus(nil)
	r1 := b.Subscribe("r1")
	r2 := b.Subscribe("r2")
	b.Publish(events.Event{RunID: "r1", Kind: "x"})
	select {
	case <-r1:
		// good
	case <-time.After(time.Second):
		t.Fatal("r1 missed event")
	}
	select {
	case ev := <-r2:
		t.Fatalf("r2 should not have received %v", ev)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestConcurrentPublishersAndSubscribers(t *testing.T) {
	// Stress: N publishers, M subscribers, all on the same run_id.
	// The bus must remain consistent under -race.
	b := events.NewBus(nil)
	const subscribers = 4
	const publishers = 8
	const eventsPer = 100

	var subs []chan events.Event
	for i := 0; i < subscribers; i++ {
		subs = append(subs, b.Subscribe("R"))
	}
	var pubWg sync.WaitGroup
	for p := 0; p < publishers; p++ {
		pubWg.Add(1)
		go func() {
			defer pubWg.Done()
			for i := 0; i < eventsPer; i++ {
				b.Publish(events.Event{RunID: "R", Kind: "k"})
			}
		}()
	}
	pubWg.Wait()

	// Each subscriber may or may not have received every event (the
	// channel buffer is QueueSize). Just confirm the channels deliver
	// at least one event each and no race-detector trip.
	for i, ch := range subs {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d received nothing", i)
		}
		b.Unsubscribe("R", ch)
	}
}
