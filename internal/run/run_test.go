package run

import "testing"

func TestStatusValid(t *testing.T) {
	for _, s := range []Status{StatusPending, StatusRunning, StatusCompleted, StatusFailed, StatusCancelled} {
		if !s.Valid() {
			t.Fatalf("%q should be valid", s)
		}
	}
	if Status("bogus").Valid() {
		t.Fatal("Status(bogus) should not be valid")
	}
}

func TestStatusIsTerminal(t *testing.T) {
	terminal := map[Status]bool{
		StatusPending: false, StatusRunning: false,
		StatusCompleted: true, StatusFailed: true, StatusCancelled: true,
	}
	for s, want := range terminal {
		if got := s.IsTerminal(); got != want {
			t.Fatalf("%q.IsTerminal() = %v, want %v", s, got, want)
		}
	}
}

func TestCanTransitionTo(t *testing.T) {
	cases := []struct {
		from, to Status
		want     bool
	}{
		// Happy path.
		{StatusPending, StatusRunning, true},
		{StatusRunning, StatusCompleted, true},
		{StatusRunning, StatusFailed, true},
		{StatusRunning, StatusCancelled, true},
		{StatusPending, StatusCancelled, true},
		// Disallowed transitions.
		{StatusPending, StatusCompleted, false},
		{StatusPending, StatusFailed, false},
		{StatusCompleted, StatusRunning, false}, // terminal frozen
		{StatusFailed, StatusRunning, false},
		{StatusCancelled, StatusPending, false},
		// Same-state.
		{StatusPending, StatusPending, false},
		{StatusRunning, StatusRunning, false},
		// Invalid target.
		{StatusPending, Status("bogus"), false},
	}
	for _, c := range cases {
		if got := c.from.CanTransitionTo(c.to); got != c.want {
			t.Fatalf("%q -> %q: got %v, want %v", c.from, c.to, got, c.want)
		}
	}
}

func TestToolExecutionStatusTerminal(t *testing.T) {
	terminal := map[ToolExecutionStatus]bool{
		ToolStatusPending: false, ToolStatusRunning: false,
		ToolStatusCompleted: true, ToolStatusFailed: true,
		ToolStatusCancelled: true, ToolStatusSkippedOutOfScope: true,
	}
	for s, want := range terminal {
		if got := s.IsTerminal(); got != want {
			t.Fatalf("%q.IsTerminal() = %v, want %v", s, got, want)
		}
		if !s.Valid() {
			t.Fatalf("%q should be valid", s)
		}
	}
	if ToolExecutionStatus("bogus").Valid() {
		t.Fatal("ToolExecutionStatus(bogus) should not be valid")
	}
}
