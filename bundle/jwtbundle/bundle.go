// Package jwtbundle provides JWT bundle types.
//
// JWT-SVID trust is outside the qspiffe-pq-v1 profile. This build keeps the
// package's identifiers so callers fail explicitly and consistently instead of
// falling back to classical token algorithms: every admission, parsing and
// lookup operation reports pqprofile.ErrUnsupported or yields no authorities.
package jwtbundle

import (
	"crypto"
	"io"
	"sync"

	"github.com/spiffe/go-spiffe/v2/internal/jwtutil"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Bundle is a collection of trusted JWT authorities for a trust domain. Under
// the strict profile it never holds any authority.
type Bundle struct {
	trustDomain spiffeid.TrustDomain

	mtx            sync.RWMutex
	jwtAuthorities map[string]crypto.PublicKey
}

// New creates a new, permanently empty bundle.
func New(trustDomain spiffeid.TrustDomain) *Bundle {
	return &Bundle{
		trustDomain:    trustDomain,
		jwtAuthorities: make(map[string]crypto.PublicKey),
	}
}

// FromJWTAuthorities returns an empty bundle. JWT authorities are not admitted
// under the strict profile; callers that can surface an error should use
// pqprofile.ErrUnsupported detection instead of relying on this constructor.
func FromJWTAuthorities(trustDomain spiffeid.TrustDomain, jwtAuthorities map[string]crypto.PublicKey) *Bundle {
	return New(trustDomain)
}

// Load is unsupported: a JWT bundle cannot be admitted under the strict profile.
func Load(trustDomain spiffeid.TrustDomain, path string) (*Bundle, error) {
	return nil, pqprofile.Unsupported("jwtbundle.Load")
}

// Read is unsupported: a JWT bundle cannot be admitted under the strict profile.
func Read(trustDomain spiffeid.TrustDomain, r io.Reader) (*Bundle, error) {
	return nil, pqprofile.Unsupported("jwtbundle.Read")
}

// Parse is unsupported: a JWT bundle cannot be admitted under the strict profile.
func Parse(trustDomain spiffeid.TrustDomain, bundleBytes []byte) (*Bundle, error) {
	return nil, pqprofile.Unsupported("jwtbundle.Parse")
}

// TrustDomain returns the trust domain that the bundle belongs to.
func (b *Bundle) TrustDomain() spiffeid.TrustDomain {
	return b.trustDomain
}

// JWTAuthorities returns an empty map. JWT authorities are outside the profile.
func (b *Bundle) JWTAuthorities() map[string]crypto.PublicKey {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return jwtutil.CopyJWTAuthorities(b.jwtAuthorities)
}

// FindJWTAuthority always reports that no authority is present.
func (b *Bundle) FindJWTAuthority(keyID string) (crypto.PublicKey, bool) {
	return nil, false
}

// HasJWTAuthority always reports that no authority is present.
func (b *Bundle) HasJWTAuthority(keyID string) bool {
	return false
}

// AddJWTAuthority is unsupported: authorities are never admitted.
func (b *Bundle) AddJWTAuthority(keyID string, jwtAuthority crypto.PublicKey) error {
	return pqprofile.Unsupported("jwtbundle.AddJWTAuthority")
}

// RemoveJWTAuthority is a no-op; the bundle never contains authorities.
func (b *Bundle) RemoveJWTAuthority(keyID string) {}

// SetJWTAuthorities is a no-op; authorities are never admitted.
func (b *Bundle) SetJWTAuthorities(jwtAuthorities map[string]crypto.PublicKey) {}

// Empty always returns true under the strict profile.
func (b *Bundle) Empty() bool {
	return true
}

// Marshal is unsupported: there is no JWT bundle representation in the profile.
func (b *Bundle) Marshal() ([]byte, error) {
	return nil, pqprofile.Unsupported("jwtbundle.Marshal")
}

// Clone clones the bundle. The clone is also empty.
func (b *Bundle) Clone() *Bundle {
	if b == nil {
		return nil
	}
	return New(b.trustDomain)
}

// Equal compares the bundle for equality against the given bundle. Since no
// authorities can be admitted, equality is trust-domain equality.
func (b *Bundle) Equal(other *Bundle) bool {
	if b == nil || other == nil {
		return b == other
	}
	return b.trustDomain == other.trustDomain
}

// GetJWTBundleForTrustDomain is unsupported: JWT bundles are not served.
func (b *Bundle) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	return nil, pqprofile.Unsupported("jwtbundle.GetJWTBundleForTrustDomain")
}
