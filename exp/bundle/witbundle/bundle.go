// Package witbundle provides WIT bundle types.
//
// WIT authorities are ML-DSA-65 AKP public keys (RFC 9964). Parsing rejects
// classical algorithms and malformed/private entries.
package witbundle

import (
	"crypto"
	"crypto/mldsa"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/spiffe/go-spiffe/v2/internal/jwtutil"
	"github.com/spiffe/go-spiffe/v2/pqjose"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const witSVIDUse = "wit-svid"

// Bundle is a collection of trusted WIT authorities for a trust domain.
type Bundle struct {
	trustDomain spiffeid.TrustDomain

	mtx            sync.RWMutex
	witAuthorities map[string]crypto.PublicKey
}

// New creates a new empty bundle for the given trust domain.
func New(trustDomain spiffeid.TrustDomain) *Bundle {
	return &Bundle{
		trustDomain:    trustDomain,
		witAuthorities: make(map[string]crypto.PublicKey),
	}
}

// FromWITAuthorities creates a new bundle from a map of WIT authorities keyed
// by key ID. Entries that are not ML-DSA-65 public keys are dropped.
func FromWITAuthorities(trustDomain spiffeid.TrustDomain, witAuthorities map[string]crypto.PublicKey) *Bundle {
	bundle := New(trustDomain)
	bundle.SetWITAuthorities(witAuthorities)
	return bundle
}

// Load loads a bundle from a file on disk. The file must contain a standard
// RFC 7517 JWKS document with ML-DSA-65 AKP keys.
func Load(trustDomain spiffeid.TrustDomain, path string) (*Bundle, error) {
	bundleBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, wrapErr(fmt.Errorf("unable to read WIT bundle: %w", err))
	}
	return Parse(trustDomain, bundleBytes)
}

// Read decodes a bundle from a reader.
func Read(trustDomain spiffeid.TrustDomain, r io.Reader) (*Bundle, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, wrapErr(fmt.Errorf("unable to read: %v", err))
	}
	return Parse(trustDomain, b)
}

// Parse parses a bundle from a JWK Set JSON document. Every entry must be an
// ML-DSA-65 AKP public key.
func Parse(trustDomain spiffeid.TrustDomain, bundleBytes []byte) (*Bundle, error) {
	keys, err := pqjose.ParseJWKS(bundleBytes)
	if err != nil {
		return nil, wrapErr(err)
	}
	bundle := New(trustDomain)
	for keyID, publicKey := range keys {
		if err := bundle.AddWITAuthority(keyID, publicKey); err != nil {
			return nil, wrapErr(err)
		}
	}
	return bundle, nil
}

// TrustDomain returns the trust domain that the bundle belongs to.
func (b *Bundle) TrustDomain() spiffeid.TrustDomain {
	return b.trustDomain
}

// WITAuthorities returns the WIT authorities in the bundle, keyed by key ID.
func (b *Bundle) WITAuthorities() map[string]crypto.PublicKey {
	b.mtx.RLock()
	defer b.mtx.RUnlock()
	return jwtutil.CopyJWTAuthorities(b.witAuthorities)
}

// FindWITAuthority finds the WIT authority with the given key ID from the
// bundle.
func (b *Bundle) FindWITAuthority(keyID string) (crypto.PublicKey, bool) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()
	authority, ok := b.witAuthorities[keyID]
	return authority, ok
}

// HasWITAuthority returns true if the bundle has a WIT authority with the
// given key ID.
func (b *Bundle) HasWITAuthority(keyID string) bool {
	b.mtx.RLock()
	defer b.mtx.RUnlock()
	_, ok := b.witAuthorities[keyID]
	return ok
}

// AddWITAuthority adds a WIT authority to the bundle.
func (b *Bundle) AddWITAuthority(keyID string, witAuthority crypto.PublicKey) error {
	if keyID == "" {
		return wrapErr(errors.New("keyID cannot be empty"))
	}
	if err := validateAuthority(witAuthority); err != nil {
		return wrapErr(err)
	}
	b.mtx.Lock()
	defer b.mtx.Unlock()
	b.witAuthorities[keyID] = witAuthority
	return nil
}

// RemoveWITAuthority removes the WIT authority identified by the key ID.
func (b *Bundle) RemoveWITAuthority(keyID string) {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	delete(b.witAuthorities, keyID)
}

// SetWITAuthorities sets the WIT authorities. Entries that are not ML-DSA-65
// public keys are dropped.
func (b *Bundle) SetWITAuthorities(witAuthorities map[string]crypto.PublicKey) {
	filtered := make(map[string]crypto.PublicKey, len(witAuthorities))
	for keyID, authority := range witAuthorities {
		if keyID != "" && validateAuthority(authority) == nil {
			filtered[keyID] = authority
		}
	}
	b.mtx.Lock()
	defer b.mtx.Unlock()
	b.witAuthorities = filtered
}

// Empty returns true if the bundle has no WIT authorities.
func (b *Bundle) Empty() bool {
	b.mtx.RLock()
	defer b.mtx.RUnlock()
	return len(b.witAuthorities) == 0
}

// Marshal marshals the WIT bundle into a JWKS document.
func (b *Bundle) Marshal() ([]byte, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	keys := make(map[string]*mldsa.PublicKey, len(b.witAuthorities))
	for keyID, authority := range b.witAuthorities {
		publicKey, ok := authority.(*mldsa.PublicKey)
		if !ok || validateAuthority(publicKey) != nil {
			return nil, wrapErr(fmt.Errorf("authority %q is not an ML-DSA-65 public key", keyID))
		}
		keys[keyID] = publicKey
	}

	encoded, err := pqjose.MarshalJWKSWithUse(witSVIDUse, keys)
	if err != nil {
		return nil, wrapErr(err)
	}
	return encoded, nil
}

// Clone clones the bundle.
func (b *Bundle) Clone() *Bundle {
	b.mtx.RLock()
	defer b.mtx.RUnlock()
	return FromWITAuthorities(b.trustDomain, b.witAuthorities)
}

// Equal compares the bundle for equality against the given bundle.
func (b *Bundle) Equal(other *Bundle) bool {
	if b == nil || other == nil {
		return b == other
	}
	return b.trustDomain == other.trustDomain &&
		jwtutil.JWTAuthoritiesEqual(b.witAuthorities, other.witAuthorities)
}

// GetWITBundleForTrustDomain returns the WIT bundle for the given trust
// domain.
func (b *Bundle) GetWITBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()
	if b.trustDomain != trustDomain {
		return nil, wrapErr(fmt.Errorf("no WIT bundle for trust domain %q", trustDomain))
	}
	return b, nil
}

func validateAuthority(witAuthority crypto.PublicKey) error {
	publicKey, ok := witAuthority.(*mldsa.PublicKey)
	if !ok {
		return fmt.Errorf("unsupported WIT authority key type %T", witAuthority)
	}
	if publicKey == nil || len(publicKey.Bytes()) != mldsa.MLDSA65().PublicKeySize() ||
		publicKey.Parameters() != mldsa.MLDSA65() {
		return errors.New("WIT authority is not an ML-DSA-65 public key")
	}
	return nil
}

func wrapErr(err error) error {
	return fmt.Errorf("witbundle: %w", err)
}
