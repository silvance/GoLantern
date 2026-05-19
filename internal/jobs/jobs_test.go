package jobs_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/silvance/golantern/internal/jobs"
)

func TestQueueDispatchesToHandler(t *testing.T) {
	var got []string
	var mu sync.Mutex
	q, err := jobs.New(func(_ context.Context, j jobs.Job) error {
		mu.Lock()
		got = append(got, j.RunID)
		mu.Unlock()
		return nil
	}, jobs.Options{Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if err := q.Submit(context.Background(), jobs.Job{RunID: id}); err != nil {
			t.Fatal(err)
		}
	}
	// Drain via Shutdown so we don't race on the slice.
	if err := q.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 3 {
		t.Fatalf("dispatched %d, want 3 (%v)", len(got), got)
	}
}

func TestQueueConcurrencyHonored(t *testing.T) {
	// With 3 workers and each handler holding a token, at most 3 jobs
	// run simultaneously. Submitting 5 must produce at least one
	// observation where in-flight == 3.
	var inflight, maxObserved int32
	const workers = 3
	start := make(chan struct{})
	q, _ := jobs.New(func(_ context.Context, _ jobs.Job) error {
		cur := atomic.AddInt32(&inflight, 1)
		for {
			prev := atomic.LoadInt32(&maxObserved)
			if cur <= prev || atomic.CompareAndSwapInt32(&maxObserved, prev, cur) {
				break
			}
		}
		<-start
		atomic.AddInt32(&inflight, -1)
		return nil
	}, jobs.Options{Concurrency: workers, BufferSize: 8})
	_ = q.Start(context.Background())

	for i := 0; i < 5; i++ {
		if err := q.Submit(context.Background(), jobs.Job{RunID: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	// Give workers a beat to pick the first batch up.
	time.Sleep(20 * time.Millisecond)
	close(start)
	_ = q.Shutdown(context.Background())

	if got := atomic.LoadInt32(&maxObserved); got < workers {
		t.Fatalf("max concurrent = %d, want >= %d", got, workers)
	}
}

func TestQueueRefusesSubmitAfterShutdown(t *testing.T) {
	q, _ := jobs.New(func(_ context.Context, _ jobs.Job) error { return nil },
		jobs.Options{Concurrency: 1})
	_ = q.Start(context.Background())
	_ = q.Shutdown(context.Background())
	if err := q.Submit(context.Background(), jobs.Job{RunID: "x"}); err == nil {
		t.Fatal("Submit after Shutdown must error")
	}
}

func TestSubmitObservesCallerContext(t *testing.T) {
	// Buffer size 1; first Submit fills the slot, second blocks until
	// ctx fires. Workers are paused so nothing drains.
	hold := make(chan struct{})
	q, _ := jobs.New(func(_ context.Context, _ jobs.Job) error {
		<-hold
		return nil
	}, jobs.Options{Concurrency: 1, BufferSize: 1})
	_ = q.Start(context.Background())
	defer func() {
		close(hold)
		_ = q.Shutdown(context.Background())
	}()

	// First fills the worker, second fills the buffer.
	_ = q.Submit(context.Background(), jobs.Job{RunID: "1"})
	_ = q.Submit(context.Background(), jobs.Job{RunID: "2"})

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	err := q.Submit(ctx, jobs.Job{RunID: "3"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want DeadlineExceeded", err)
	}
}

func TestHandlerErrorsAreLoggedNotPropagated(t *testing.T) {
	// We can't easily assert on the slog output; just confirm that a
	// handler error doesn't crash the worker and subsequent jobs still
	// execute.
	var count atomic.Int32
	q, _ := jobs.New(func(_ context.Context, j jobs.Job) error {
		count.Add(1)
		if j.RunID == "bad" {
			return errors.New("intentional test failure")
		}
		return nil
	}, jobs.Options{Concurrency: 1})
	_ = q.Start(context.Background())
	for _, id := range []string{"bad", "good"} {
		_ = q.Submit(context.Background(), jobs.Job{RunID: id})
	}
	_ = q.Shutdown(context.Background())
	if count.Load() != 2 {
		t.Fatalf("handler invoked %d times, want 2", count.Load())
	}
}

func TestSubmitDetachesJobCtxFromCallerCtx(t *testing.T) {
	// The job context handed to the handler must NOT be cancelled when
	// the Submit caller's context is cancelled. Operators expect "API
	// returned 201" to mean "queue accepted my work", not "work
	// terminates if I close my browser".
	done := make(chan struct{})
	q, _ := jobs.New(func(jctx context.Context, _ jobs.Job) error {
		<-time.After(20 * time.Millisecond)
		select {
		case <-jctx.Done():
			// Bad: caller's cancellation leaked through.
			t.Errorf("job context was cancelled")
		default:
		}
		close(done)
		return nil
	}, jobs.Options{Concurrency: 1})
	_ = q.Start(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	_ = q.Submit(ctx, jobs.Job{RunID: "x"})
	cancel() // simulate request ending immediately after enqueue
	<-done
	_ = q.Shutdown(context.Background())
}
