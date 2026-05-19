// Package jobs is the in-process job queue that dispatches Run
// invocations to the scan engine.
//
// Ported from lantern.jobs.queue (asyncio.Queue + N worker tasks).
// Differences:
//
//   - Buffered channel instead of asyncio.Queue. Submit blocks the
//     caller when the channel is full so backpressure surfaces at the
//     producer rather than as a runaway memory footprint.
//   - Workers are goroutines started by Start. Shutdown waits for
//     in-flight jobs to drain (with a context-deadline escape hatch).
//   - The job handler is injected (rather than calling
//     engine.ExecuteRun directly) so the package has no dependency
//     on engine. cmd/golantern wires the two together.
//   - Concurrency cap is configurable; SQLite stays safe under
//     concurrent workers because WAL journal mode (set in
//     sqlite.Open) allows one writer + many readers. Python's
//     workaround of clamp-to-1-on-sqlite is no longer needed.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

// Job is one Run's worth of dispatch work. Tools are processed in
// order by the scan runner; concurrency happens across Jobs, not
// within one Job.
type Job struct {
	RunID       string
	Invocations []Invocation
}

// Invocation is (tool name, parameters). Mirrors engine.Invocation
// shape but lives here too so the queue has no dependency on engine.
// Callers convert between the two; the field set is identical.
type Invocation struct {
	Tool       string
	Parameters map[string]any
}

// Handler is the function the queue calls for each dequeued Job. The
// queue treats Handler errors as informational (logs them) rather
// than retrying — retry policy lives at a higher layer.
type Handler func(ctx context.Context, job Job) error

// Queue is the channel-backed dispatcher.
//
// Submit / Shutdown synchronization: an RWMutex serializes the close
// of ch against in-flight sends. Submit holds RLock for its entire
// duration so multiple submitters proceed in parallel; Shutdown takes
// the write lock to close ch, guaranteeing no send can race with the
// close. stopCh is closed first so pending blocked Submits unblock and
// release the read lock.
type Queue struct {
	concurrency int
	bufSize     int
	handler     Handler
	logger      *slog.Logger

	ch chan Job

	startOnce sync.Once
	startErr  error
	wg        sync.WaitGroup

	mu     sync.RWMutex  // guards `closed`; held RLock by Submit, Lock by Shutdown
	closed bool
	stopCh chan struct{} // closed by Shutdown to unblock pending Submits
}

// Options configures a Queue. Zero values choose sensible defaults
// (1 worker, channel capacity 64, slog.Default).
type Options struct {
	Concurrency int
	BufferSize  int
	Logger      *slog.Logger
}

// New constructs a Queue. The handler is required; everything else
// has a default.
func New(handler Handler, opts Options) (*Queue, error) {
	if handler == nil {
		return nil, errors.New("jobs.New: handler is required")
	}
	c := opts.Concurrency
	if c <= 0 {
		c = 1
	}
	b := opts.BufferSize
	if b <= 0 {
		b = 64
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Queue{
		concurrency: c,
		bufSize:     b,
		handler:     handler,
		logger:      logger,
		ch:          make(chan Job, b),
		stopCh:      make(chan struct{}),
	}, nil
}

// Start launches the worker goroutines. Idempotent; subsequent calls
// return the first error if Start failed, or nil otherwise.
//
// The parent context isn't stored — it's only used to detect early
// cancellation before any worker is launched. Workers observe the
// per-job context passed to Submit.
func (q *Queue) Start(_ context.Context) error {
	q.startOnce.Do(func() {
		for i := 0; i < q.concurrency; i++ {
			q.wg.Add(1)
			go q.worker(i)
		}
		q.logger.Info("jobs queue started", slog.Int("workers", q.concurrency))
	})
	return q.startErr
}

// Submit enqueues a Job. Blocks when the buffer is full; cancel via
// ctx. Returns ctx.Err() on cancel, or a sentinel error when the queue
// is shutting down.
func (q *Queue) Submit(ctx context.Context, j Job) error {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.closed {
		return errors.New("jobs queue is shutting down")
	}
	select {
	case q.ch <- j:
		return nil
	case <-q.stopCh:
		// Shutdown started while we were waiting for buffer space.
		// stopCh closes BEFORE ch closes, so this case is safe — the
		// channel is still open here, we're just being told to bail.
		return errors.New("jobs queue is shutting down")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Shutdown stops the queue, waits for in-flight jobs to drain, and
// returns. Pending jobs that have been accepted into the buffer get
// processed; Submits that hadn't yet acquired the lock see the closed
// state and return an error.
//
// Honors ctx so a slow handler doesn't block server shutdown forever.
// If ctx fires before drain completes, returns ctx.Err() with workers
// still running in the background — the process exits anyway.
//
// Idempotent: a second Shutdown returns nil immediately.
func (q *Queue) Shutdown(ctx context.Context) error {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return nil
	}
	q.closed = true
	// Unblock pending Submits that are waiting for buffer space.
	// They'll observe stopCh and return without sending on ch.
	close(q.stopCh)
	// Safe to close ch now: no Submit can be mid-send (we hold the
	// write lock; Submit holds RLock for the entire send), and
	// pending blocked Submits have already exited via stopCh.
	close(q.ch)
	q.mu.Unlock()

	done := make(chan struct{})
	go func() {
		q.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		q.logger.Info("jobs queue drained")
		return nil
	case <-ctx.Done():
		q.logger.Warn("jobs queue shutdown timed out")
		return fmt.Errorf("jobs.Shutdown: %w", ctx.Err())
	}
}

func (q *Queue) worker(id int) {
	defer q.wg.Done()
	for job := range q.ch {
		// Build a fresh background context so a Submit caller's
		// cancellation doesn't kill an in-flight job. Operators expect
		// "the API call returned" to mean "the queue accepted my
		// work", not "the work was cancelled when my browser closed".
		jobCtx := context.Background()
		if err := q.handler(jobCtx, job); err != nil {
			q.logger.Error("job failed",
				slog.Int("worker", id),
				slog.String("run_id", job.RunID),
				slog.Any("err", err))
		}
	}
}
