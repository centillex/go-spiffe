// Package witbundle provides WIT bundle types.
//
// WIT trust is outside the qspiffe-pq-v1 profile. This build keeps the
// package's identifiers so callers fail explicitly and consistently instead of
// falling back to classical token algorithms: every admission, parsing and
// lookup operation reports pqprofile.ErrUnsupported or yields no authorities.
package witbundle

import (
	"crypto"
	"io"
	"sync"

	"github.com/spiffe/go-spiffe/v2/internal/jwtutil"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Bundle is a collection of trusted WIT authorities for a trust domain. Under
// the strict profile it never holds any authority.
type Bundle struct {
	trustDomain spiffeid.TrustDomain

	mtx            sync.RWMutex
	witAuthorities map[string]crypto.PublicKey
}

// New creates a new, permanently empty bundle for the given trust domain.
func New(trustDomain spiffeid.TrustDomain) *Bundle {
	return &Bundle{
		trustDomain:    trustDomain,
		witAuthorities: make(map[string]crypto.PublicKey),
	}
}

// FromWITAuthorities returns an empty bundle. WIT authorities are not admitted
// under the strict profile; callers that can surface an error should use
// pqprofile.ErrUnsupported detection instead of relying on this constructor.
func FromWITAuthorities(trustDomain spiffeid.TrustDomain, witAuthorities map[string]crypto.PublicKey) *Bundle {
	return New(trustDomain)
}

// Load is unsupported: a WIT bundle cannot be admitted under the strict profile.
func Load(trustDomain spiffeid.TrustDomain, path string) (*Bundle, error) {
	return nil, pqprofile.Unsupported("witbundle.Load")
}

// Read is unsupported: a WIT bundle cannot be admitted under the strict profile.
func Read(trustDomain spiffeid.TrustDomain, r io.Reader) (*Bundle, error) {
	return nil, pqprofile.Unsupported("witbundle.Read")
}

// Parse is unsupported: a WIT bundle cannot be admitted under the strict profile.
func Parse(trustDomain spiffeid.TrustDomain, bundleBytes []byte) (*Bundle, error) {
	return nil, pqprofile.Unsupported("witbundle.Parse")
}

// TrustDomain returns the trust domain that the bundle belongs to.
func (b *Bundle) TrustDomain() spiffeid.TrustDomain {
	return b.trustDomain
}

// WITAuthorities returns an empty map. WIT authorities are outside the profile.
func (b *Bundle) WITAuthorities() map[string]crypto.PublicKey {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return jwtutil.CopyJWTAuthorities(b.witAuthorities)
}

// FindWITAuthority always reports that no authority is present.
func (b *Bundle) FindWITAuthority(keyID string) (crypto.PublicKey, bool) {
	return nil, false
}

// HasWITAuthority always reports that no authority is present.
func (b *Bundle) HasWITAuthority(keyID string) bool {
	return false
}

// AddWITAuthority is unsupported: authorities are never admitted.
func (b *Bundle) AddWITAuthority(keyID string, witAuthority crypto.PublicKey) error {
	return pqprofile.Unsupported("witbundle.AddWITAuthority")
}

// RemoveWITAuthority is a no-op; the bundle never contains authorities.
func (b *Bundle) RemoveWITAuthority(keyID string) {}

// SetWITAuthorities is a no-op; authorities are never admitted.
func (b *Bundle) SetWITAuthorities(witAuthorities map[string]crypto.PublicKey) {}

// Empty always returns true under the strict profile.
func (b *Bundle) Empty() bool {
	return true
}

// Marshal is unsupported: there is no WIT bundle representation in the profile.
func (b *Bundle) Marshal() ([]byte, error) {
	return nil, pqprofile.Unsupported("witbundle.Marshal")
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

// GetWITBundleForTrustDomain is unsupported: WIT bundles are not served.
func (b *Bundle) GetWITBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	return nil, pqprofile.Unsupported("witbundle.GetWITBundleForTrustDomain")
}
