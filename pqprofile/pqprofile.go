// Package pqprofile exposes the qspiffe-pq-v1 profile boundary to callers.
//
// This build implements the strict post-quantum profile: ML-DSA-65
// authentication over TLS 1.3 with approved hybrid key exchange. JWT-SVID,
// WIT-SVID, and their trust bundles are outside the profile and are rejected
// at every public entry point instead of falling back to classical algorithms.
package pqprofile

import (
	"errors"
	"fmt"
)

// ErrUnsupported is returned by every public JWT-SVID, WIT, and token-bundle
// operation in this build. Use errors.Is to detect it.
var ErrUnsupported = errors.New("qspiffe-pq-v1: JWT-SVID and WIT are unsupported")

// Unsupported wraps ErrUnsupported with the calling operation for diagnostics.
func Unsupported(operation string) error {
	return fmt.Errorf("%s: %w", operation, ErrUnsupported)
}
