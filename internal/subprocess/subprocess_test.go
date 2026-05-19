package subprocess_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/silvance/golantern/internal/subprocess"
)

// writeScript writes body as an executable file under t.TempDir() and
// returns the absolute path. The shebang and chmod let exec.LookPath
// find it and the OS run it directly.
func writeScript(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("script-based tests use /bin/sh")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunBinaryNotFound(t *testing.T) {
	_, err := subprocess.Run(context.Background(), subprocess.Spec{
		Binary:  "this-binary-does-not-exist-anywhere",
		Timeout: time.Second,
	})
	if !errors.Is(err, subprocess.ErrBinaryNotFound) {
		t.Fatalf("got %v, want chain ending in ErrBinaryNotFound", err)
	}
	var nfe *subprocess.BinaryNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("error not assignable to *BinaryNotFoundError: %v", err)
	}
	if nfe.Binary == "" {
		t.Fatal("Binary should be set on the error")
	}
}

func TestRunHappyPath(t *testing.T) {
	path := writeScript(t, "echo hello world\n>&2 echo a stderr line")
	res, err := subprocess.Run(context.Background(), subprocess.Spec{
		Binary:  path,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "hello world" {
		t.Fatalf("stdout=%q", got)
	}
	if got := strings.TrimSpace(string(res.Stderr)); got != "a stderr line" {
		t.Fatalf("stderr=%q", got)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d", res.ExitCode)
	}
}

func TestRunNonZeroExitFailsByDefault(t *testing.T) {
	path := writeScript(t, ">&2 echo boom\nexit 2")
	_, err := subprocess.Run(context.Background(), subprocess.Spec{
		Binary:  path,
		Timeout: 5 * time.Second,
	})
	var exitErr *subprocess.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("got %v, want *ExitError", err)
	}
	if exitErr.ExitCode != 2 {
		t.Fatalf("exit=%d, want 2", exitErr.ExitCode)
	}
	if !strings.Contains(exitErr.Error(), "boom") {
		t.Fatalf("error missing stderr tail: %q", exitErr.Error())
	}
}

func TestRunAllowedPartialRC(t *testing.T) {
	// rc=1 with valid output: success when in AllowPartialRC.
	path := writeScript(t, "echo partial\nexit 1")
	res, err := subprocess.Run(context.Background(), subprocess.Spec{
		Binary:         path,
		Timeout:        5 * time.Second,
		AllowPartialRC: []int{1},
	})
	if err != nil {
		t.Fatalf("partial-rc should pass; got %v", err)
	}
	if strings.TrimSpace(string(res.Stdout)) != "partial" {
		t.Fatalf("stdout=%q", res.Stdout)
	}
	if res.ExitCode != 1 {
		t.Fatalf("exit=%d, want 1", res.ExitCode)
	}
}

func TestRunTimeoutKillsProcess(t *testing.T) {
	path := writeScript(t, "sleep 5\necho should-not-arrive")
	start := time.Now()
	_, err := subprocess.Run(context.Background(), subprocess.Spec{
		Binary:  path,
		Timeout: 100 * time.Millisecond,
	})
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("Run waited %v, should kill at timeout", elapsed)
	}
	var to *subprocess.TimeoutError
	if !errors.As(err, &to) {
		t.Fatalf("got %v, want *TimeoutError", err)
	}
	if to.Timeout != 100*time.Millisecond {
		t.Fatalf("Timeout=%v", to.Timeout)
	}
}

func TestRunCallerContextCancel(t *testing.T) {
	path := writeScript(t, "sleep 5")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := subprocess.Run(ctx, subprocess.Spec{
		Binary:  path,
		Timeout: 5 * time.Second,
	})
	if time.Since(start) > 2*time.Second {
		t.Fatalf("caller-cancel didn't propagate")
	}
	if err == nil {
		t.Fatal("expected error from caller cancellation")
	}
}

func TestRunStdinPipes(t *testing.T) {
	path := writeScript(t, "cat")
	res, err := subprocess.Run(context.Background(), subprocess.Spec{
		Binary:  path,
		Stdin:   []byte("piped input\n"),
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(res.Stdout)) != "piped input" {
		t.Fatalf("stdout=%q", res.Stdout)
	}
}

func TestRunArgsForwarded(t *testing.T) {
	path := writeScript(t, `echo "$@"`)
	res, err := subprocess.Run(context.Background(), subprocess.Spec{
		Binary:  path,
		Args:    []string{"--alpha", "beta gamma", "delta"},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "--alpha beta gamma delta" {
		t.Fatalf("args lost: %q", got)
	}
}

func TestRunRejectsZeroTimeout(t *testing.T) {
	_, err := subprocess.Run(context.Background(), subprocess.Spec{
		Binary: "sh",
	})
	if err == nil || !strings.Contains(err.Error(), "Timeout") {
		t.Fatalf("expected explicit error about Timeout; got %v", err)
	}
}

func TestRunRejectsEmptyBinary(t *testing.T) {
	_, err := subprocess.Run(context.Background(), subprocess.Spec{
		Binary:  "",
		Timeout: time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "Binary") {
		t.Fatalf("expected explicit error about Binary; got %v", err)
	}
}

func TestExitErrorMessageIncludesTail(t *testing.T) {
	path := writeScript(t, `for i in 1 2 3 4 5 6 7 8; do echo "line $i" >&2; done; exit 3`)
	_, err := subprocess.Run(context.Background(), subprocess.Spec{
		Binary:  path,
		Timeout: 5 * time.Second,
	})
	// Should include the last 5 lines of stderr.
	if err == nil || !strings.Contains(err.Error(), "line 4") {
		t.Fatalf("tail missing line 4: %v", err)
	}
	if !strings.Contains(err.Error(), "line 8") {
		t.Fatalf("tail missing line 8: %v", err)
	}
	// Should NOT include line 1/2/3 (only the last 5).
	if strings.Contains(err.Error(), "line 1 ") || strings.Contains(err.Error(), "line 2 ") {
		t.Fatalf("tail too long: %v", err)
	}
}
