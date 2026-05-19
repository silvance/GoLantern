package id

import (
	"regexp"
	"testing"
)

var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)

func TestNewFormat(t *testing.T) {
	got := New()
	if !hex32.MatchString(got) {
		t.Fatalf("New() = %q, want 32 hex chars", got)
	}
}

func TestNewUnique(t *testing.T) {
	const n = 1000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		v := New()
		if _, dup := seen[v]; dup {
			t.Fatalf("collision after %d ids: %q", i, v)
		}
		seen[v] = struct{}{}
	}
}

func TestNewSetsVersionAndVariantBits(t *testing.T) {
	// UUID4: byte 6 high nibble == 4, byte 8 high two bits == 10
	v := New()
	// Bytes 6 and 8 sit at hex positions 12-13 and 16-17.
	if v[12] != '4' {
		t.Fatalf("version nibble = %c, want 4", v[12])
	}
	if v[16] < '8' || v[16] > 'b' {
		t.Fatalf("variant nibble = %c, want one of 8,9,a,b", v[16])
	}
}
