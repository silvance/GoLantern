package finding

import (
	"sort"
	"testing"
)

func TestSeverityAtLeast(t *testing.T) {
	cases := []struct {
		actual, threshold Severity
		want              bool
	}{
		{SeverityCritical, SeverityHigh, true},
		{SeverityHigh, SeverityHigh, true},
		{SeverityMedium, SeverityHigh, false},
		{SeverityInfo, SeverityInfo, true},
		{Severity("bogus"), SeverityInfo, false},
		{SeverityInfo, Severity("bogus"), false},
	}
	for _, c := range cases {
		if got := c.actual.AtLeast(c.threshold); got != c.want {
			t.Fatalf("AtLeast(actual=%s,threshold=%s) = %v, want %v",
				c.actual, c.threshold, got, c.want)
		}
	}
}

func TestSeveritySortOrder(t *testing.T) {
	// Critical first, info last. Sorting findings by SortKey ascending
	// should produce that order.
	in := []Severity{SeverityInfo, SeverityCritical, SeverityLow, SeverityHigh, SeverityMedium}
	sort.SliceStable(in, func(i, j int) bool { return in[i].SortKey() < in[j].SortKey() })
	want := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
	for i := range in {
		if in[i] != want[i] {
			t.Fatalf("sort mismatch at %d: got %s, want %s", i, in[i], want[i])
		}
	}
}

func TestUnknownSeveritySortsLast(t *testing.T) {
	in := []Severity{SeverityInfo, Severity("bogus"), SeverityCritical}
	sort.SliceStable(in, func(i, j int) bool { return in[i].SortKey() < in[j].SortKey() })
	if in[len(in)-1] != Severity("bogus") {
		t.Fatalf("unknown severity should sort last; got %v", in)
	}
}

func TestConfidenceAndSourceValid(t *testing.T) {
	for _, c := range []Confidence{ConfidenceLow, ConfidenceMedium, ConfidenceHigh, ConfidenceConfirmed} {
		if !c.Valid() {
			t.Fatalf("%q should be valid", c)
		}
	}
	if Confidence("nope").Valid() {
		t.Fatal("bogus Confidence should not be valid")
	}
	for _, s := range []SourceCategory{SourcePublicOSINT, SourceActiveScan, SourceManual} {
		if !s.Valid() {
			t.Fatalf("%q should be valid", s)
		}
	}
	if SourceCategory("nope").Valid() {
		t.Fatal("bogus SourceCategory should not be valid")
	}
}
