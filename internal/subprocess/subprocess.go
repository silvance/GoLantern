// Package subprocess centralizes the boilerplate every collector that
// shells out would otherwise duplicate: PATH lookup, spawn, timeout
// handling with kill-on-timeout, exit-code discrimination, and
// stderr-tail surfacing in the error message.
//
// Mirrors lantern.subprocess. Caller-friendly error types stay here
// (ErrBinaryNotFound, *TimeoutError, *ExitError); collector packages
// wrap them with their own sentinel when context is needed.
package subprocess

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// ErrBinaryNotFound is returned by Run when the requested binary
// isn't on PATH. Distinct from generic execution errors because this
// is a known operator-setup case (collector queued for a CLI they
// haven't installed) — the scan runner downgrades it to a warning
// without a traceback, and the SPA surfaces a "install this tool"
// message instead of a generic failure.
var ErrBinaryNotFound = errors.New("subprocess: binary not found on PATH")

// BinaryNotFoundError carries which binary was missing so the SPA can
// render a precise install-this hint. Unwraps to ErrBinaryNotFound.
type BinaryNotFoundError struct {
	Binary string
}

func (e *BinaryNotFoundError) Error() string {
	return fmt.Sprintf("subprocess: %q is not installed (not found on PATH). "+
		"Install the tool and rerun, or queue a different collector.", e.Binary)
}

func (e *BinaryNotFoundError) Unwrap() error { return ErrBinaryNotFound }

// TimeoutError is returned when the child process was killed because
// it exceeded Spec.Timeout. The killed process's partial output is
// captured on the wrapped Result so callers can still surface useful
// diagnostics.
type TimeoutError struct {
	Binary  string
	Timeout time.Duration
	Result  Result
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("subprocess: %q timed out after %s", e.Binary, e.Timeout)
}

// ExitError is returned when the process exited with a non-zero code
// that isn't listed in Spec.AllowPartialRC. The last few lines of
// stderr (or stdout, when stderr is empty) are included in the message
// so callers don't have to chase a separate diagnostic.
type ExitError struct {
	Binary   string
	ExitCode int
	Result   Result
}

func (e *ExitError) Error() string {
	tail := stderrTail(e.Result.Stderr, e.Result.Stdout, 5)
	if tail == "" {
		return fmt.Sprintf("subprocess: %q exited rc=%d", e.Binary, e.ExitCode)
	}
	return fmt.Sprintf("subprocess: %q exited rc=%d: %s", e.Binary, e.ExitCode, tail)
}

// Spec describes one invocation. Zero values for non-required fields
// give sane defaults; Timeout is required (a missing budget would
// trivially hang the worker on a runaway subprocess).
type Spec struct {
	Binary  string        // e.g. "nmap"
	Args    []string      // flags + positional args, in order
	Stdin   []byte        // optional; nil means no stdin
	Timeout time.Duration // wall-clock budget; 0 is rejected
	// AllowPartialRC is the set of non-zero exit codes treated as
	// success (with whatever output the process produced). nmap is
	// the canonical example: rc=1 with valid XML is normal for any
	// scan of a partially-live range.
	AllowPartialRC []int
	// Env is an optional environment slice. Zero/nil inherits the
	// parent's environment.
	Env []string
}

// Result is what every Run returns on a non-error completion. The
// fields stay populated for TimeoutError / ExitError too so callers
// can show partial output.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Run executes spec under ctx. Returns ErrBinaryNotFound /
// BinaryNotFoundError when the binary is missing, *TimeoutError on
// budget expiry, *ExitError on a non-zero unallowed exit, and a
// generic wrapped error for anything else.
//
// The caller's ctx and spec.Timeout combine: cancellation of ctx
// kills the process; the timeout adds an upper bound so a request
// that forgets to cancel can't pin a worker.
func Run(ctx context.Context, spec Spec) (Result, error) {
	if spec.Timeout <= 0 {
		return Result{}, errors.New("subprocess.Run: Timeout must be > 0")
	}
	if spec.Binary == "" {
		return Result{}, errors.New("subprocess.Run: Binary is required")
	}
	if _, err := exec.LookPath(spec.Binary); err != nil {
		return Result{}, &BinaryNotFoundError{Binary: spec.Binary}
	}

	runCtx, cancel := context.WithTimeout(ctx, spec.Timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, spec.Binary, spec.Args...)
	if spec.Env != nil {
		cmd.Env = spec.Env
	}
	if spec.Stdin != nil {
		cmd.Stdin = bytes.NewReader(spec.Stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// WaitDelay bounds how long Wait blocks after Cancel kills the
	// process leader. Without it, a child that's reparented to init
	// (e.g. a `sleep` spawned by a killed shell script) keeps stdout
	// open and Wait blocks forever. 500ms is plenty for a SIGKILL'd
	// process to release its pipes; in the timeout/cancel path we'd
	// already be returning an error so the extra latency is invisible.
	cmd.WaitDelay = 500 * time.Millisecond

	err := cmd.Run()
	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}

	// Order matters: a timeout shows up as either context.DeadlineExceeded
	// on runCtx or a -1 exit code on the killed process. Check ctx
	// first so we surface the more useful TimeoutError.
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return res, &TimeoutError{Binary: spec.Binary, Timeout: spec.Timeout, Result: res}
	}

	if err == nil {
		return res, nil
	}

	// Distinguish exit-code failure from spawn-side errors so callers
	// can match on *ExitError without confusing it with EPERM / etc.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		rc := exitErr.ExitCode()
		for _, allowed := range spec.AllowPartialRC {
			if rc == allowed {
				return res, nil
			}
		}
		return res, &ExitError{Binary: spec.Binary, ExitCode: rc, Result: res}
	}
	return res, fmt.Errorf("subprocess.Run: %w", err)
}

// stderrTail returns up to n trailing non-blank lines of stderr (or
// stdout, when stderr is empty) as a single string joined with " | ".
// Matches the Python implementation's "last 5 lines" diagnostic.
func stderrTail(stderr, stdout []byte, n int) string {
	src := stderr
	if len(src) == 0 {
		src = stdout
	}
	if len(src) == 0 {
		return ""
	}
	text := strings.TrimRight(string(src), "\r\n")
	if text == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	// Drop blank trailing lines.
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// Reader is a convenience wrapper for callers that already have an
// io.Reader for stdin. Not strictly needed; documents the intent.
func StdinFromReader(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	return io.ReadAll(r)
}
