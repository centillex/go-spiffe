// Package pqprofile exposes the qspiffe-pq-v1 profile boundary to callers.
//
// This build implements the strict post-quantum profile: ML-DSA-65
// authentication over TLS 1.3 with approved hybrid key exchange. X.509-SVID,
// ML-DSA-65 JWT-SVID and ML-DSA-65 WIT-SVID are admitted.
package pqprofile

import (
	"errors"
	"fmt"
)

// ErrUnsupported is retained for source compatibility. All token formats in
// this profile are implemented; the sentinel is no longer returned by a
// supported token path.
var ErrUnsupported = errors.New("qspiffe-pq-v1: unsupported operation")

// Unsupported wraps ErrUnsupported with the calling operation for diagnostics.
func Unsupported(operation string) error {
	return fmt.Errorf("%s: %w", operation, ErrUnsupported)
}
