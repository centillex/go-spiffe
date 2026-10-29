// Package pqprofile exposes the qspiffe-pq-v1 profile boundary to callers.
//
// This build implements the strict post-quantum profile: ML-DSA-65
// authentication over TLS 1.3 with approved hybrid key exchange. X.509-SVID
// and ML-DSA-65 JWT-SVID are admitted. WIT-SVID remains outside the profile
// until its proof-of-possession format is implemented.
package pqprofile

import (
	"errors"
	"fmt"
)

// ErrUnsupported is returned by every public WIT-SVID and WIT-bundle
// operation in this build. Use errors.Is to detect it.
var ErrUnsupported = errors.New("qspiffe-pq-v1: WIT-SVID is unsupported")

// Unsupported wraps ErrUnsupported with the calling operation for diagnostics.
func Unsupported(operation string) error {
	return fmt.Errorf("%s: %w", operation, ErrUnsupported)
}
