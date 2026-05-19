// Package events is the in-process pub/sub broadcaster for live run
// progress. Mirrors lantern.events.RunEventBus.
//
// One bucket per run_id; subscribers get their own buffered channel
// and are responsible for consuming promptly. Publish is non-blocking:
// a full subscriber channel drops the event with a warning rather
// than back-pressuring the collector — preserving collection
// throughput is the explicit tradeoff. Subscribers that need every
// event must drain on time.
package events

import (
	"log/slog"
	"sync"
	"time"
)

// Event kinds. New kinds may be added freely; subscribers ignore
// unknown ones.
const (
	KindRunStarted       = "run.started"
	KindRunFinished      = "run.finished"
	KindToolStarted      = "tool.started"
	KindToolFinished     = "tool.finished"
	KindEntityEmitted    = "entity.emitted"
	KindRelationEmitted  = "relation.emitted"
	KindEvidenceEmitted  = "evidence.emitted"
	KindFindingEmitted   = "finding.emitted"
)

// Event carries one observation. Timestamp is stamped at publish time.
// Payload should be a small map of JSON-safe values; the SSE handler
// json.Marshals it verbatim.
type Event struct {
	RunID     string         `json:"run_id"`
	Kind      string         `json:"kind"`
	Payload   map[string]any `json:"payload,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}

// QueueSize is the per-subscriber channel buffer. Matches Python's
// RunEventBus.QUEUE_MAX_SIZE. A subscriber slower than this is dropped
// rather than slowing the collector.
const QueueSize = 1024

// Bus is the broadcaster. Safe for concurrent Subscribe / Publish /
// Unsubscribe; reads of subscriber buckets happen under RLock so
// publishes proceed in parallel.
type Bus struct {
	mu          sync.RWMutex
	subscribers map[string]map[chan Event]struct{}
	logger      *slog.Logger
}

// NewBus constructs an empty Bus. Logger defaults to slog.Default
// when nil.
func NewBus(logger *slog.Logger) *Bus {
	if logger == nil {
		logger = slog.Default()
	}
	return &Bus{
		subscribers: make(map[string]map[chan Event]struct{}),
		logger:      logger,
	}
}

// Subscribe returns a fresh buffered channel that receives every
// Event for runID. Callers MUST call Unsubscribe when done so the
// bus doesn't retain references forever.
//
// The buffer absorbs short consumer stalls. A subscriber that
// blocks beyond QueueSize loses subsequent events; the bus logs at
// warn level and continues.
func (b *Bus) Subscribe(runID string) chan Event {
	ch := make(chan Event, QueueSize)
	b.mu.Lock()
	defer b.mu.Unlock()
	bucket, ok := b.subscribers[runID]
	if !ok {
		bucket = make(map[chan Event]struct{})
		b.subscribers[runID] = bucket
	}
	bucket[ch] = struct{}{}
	return ch
}

// Unsubscribe removes ch from the runID bucket and closes the
// channel so any blocked receiver sees io.EOF / range-loop exit.
// Idempotent; a second call on the same channel is a no-op.
func (b *Bus) Unsubscribe(runID string, ch chan Event) {
	b.mu.Lock()
	bucket, ok := b.subscribers[runID]
	if !ok {
		b.mu.Unlock()
		return
	}
	if _, present := bucket[ch]; !present {
		b.mu.Unlock()
		return
	}
	delete(bucket, ch)
	if len(bucket) == 0 {
		delete(b.subscribers, runID)
	}
	b.mu.Unlock()
	close(ch)
}

// Publish fans an event out to every subscriber of e.RunID.
// Non-blocking: a full subscriber channel drops the event and a
// warning is logged. Returns the count of subscribers reached
// (useful in tests).
//
// Stamps Timestamp at publish time when zero. Caller may pre-set it.
func (b *Bus) Publish(e Event) int {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	b.mu.RLock()
	bucket, ok := b.subscribers[e.RunID]
	if !ok {
		b.mu.RUnlock()
		return 0
	}
	// Snapshot the channel set under the read lock; do the actual
	// sends after releasing it so a slow receiver can't block other
	// publishers.
	chans := make([]chan Event, 0, len(bucket))
	for ch := range bucket {
		chans = append(chans, ch)
	}
	b.mu.RUnlock()

	delivered := 0
	for _, ch := range chans {
		select {
		case ch <- e:
			delivered++
		default:
			b.logger.Warn("events: subscriber queue full, dropping",
				slog.String("run_id", e.RunID),
				slog.String("kind", e.Kind))
		}
	}
	return delivered
}

// SubscriberCount returns how many subscribers are listening on
// runID. Test-only helper; the bus doesn't otherwise expose internals.
func (b *Bus) SubscriberCount(runID string) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subscribers[runID])
}
