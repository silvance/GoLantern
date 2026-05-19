// Package id mints opaque identifiers for domain objects.
//
// Mirrors lantern.models.base.new_id (uuid4().hex). 32-char hex string,
// no dashes. We use crypto/rand directly rather than depending on an
// external uuid package — the format is a UUID4 only by convention
// (random 128 bits with the version/variant bits set), and an explicit
// implementation removes a dependency for a six-line function.
package id

import (
	"crypto/rand"
	"encoding/hex"
)

// New returns a fresh 32-char hex identifier. Panics on the unrecoverable
// case where crypto/rand fails — that means the OS entropy source is
// broken and no useful work can continue.
func New() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("id: crypto/rand failed: " + err.Error())
	}
	// Set version (4) and variant (RFC 4122) bits so the result is a
	// valid UUID4 if anyone ever parses it that way.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[:])
}
