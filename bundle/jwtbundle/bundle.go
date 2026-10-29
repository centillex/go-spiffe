package jwtbundle

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

// Bundle is a collection of trusted JWT authorities for a trust domain.
//
// Only ML-DSA-65 AKP authorities (RFC 9964) are admitted. Classical JWT
// algorithms are rejected so the strict post-quantum profile has no fallback.
type Bundle struct {
	trustDomain spiffeid.TrustDomain

	mtx            sync.RWMutex
	jwtAuthorities map[string]crypto.PublicKey
}

// New creates a new bundle.
func New(trustDomain spiffeid.TrustDomain) *Bundle {
	return &Bundle{
		trustDomain:    trustDomain,
		jwtAuthorities: make(map[string]crypto.PublicKey),
	}
}

// FromJWTAuthorities creates a new bundle from JWT authorities. Authors
// whose key is not an ML-DSA-65 public key are dropped.
func FromJWTAuthorities(trustDomain spiffeid.TrustDomain, jwtAuthorities map[string]crypto.PublicKey) *Bundle {
	bundle := New(trustDomain)
	bundle.SetJWTAuthorities(jwtAuthorities)
	return bundle
}

// Load loads a bundle from a file on disk. The file must contain a standard
// RFC 7517 JWKS document with ML-DSA-65 AKP keys.
func Load(trustDomain spiffeid.TrustDomain, path string) (*Bundle, error) {
	bundleBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, wrapJwtbundleErr(fmt.Errorf("unable to read JWT bundle: %w", err))
	}

	return Parse(trustDomain, bundleBytes)
}

// Read decodes a bundle from a reader. The contents must contain a standard
// RFC 7517 JWKS document with ML-DSA-65 AKP keys.
func Read(trustDomain spiffeid.TrustDomain, r io.Reader) (*Bundle, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, wrapJwtbundleErr(fmt.Errorf("unable to read: %v", err))
	}

	return Parse(trustDomain, b)
}

// Parse parses a bundle from bytes. Every entry must be an ML-DSA-65 AKP
// public key; unknown or classical entries fail the parse instead of being
// ignored.
func Parse(trustDomain spiffeid.TrustDomain, bundleBytes []byte) (*Bundle, error) {
	keys, err := pqjose.ParseJWKS(bundleBytes)
	if err != nil {
		return nil, wrapJwtbundleErr(err)
	}

	bundle := New(trustDomain)
	for keyID, publicKey := range keys {
		if err := bundle.AddJWTAuthority(keyID, publicKey); err != nil {
			return nil, wrapJwtbundleErr(err)
		}
	}

	return bundle, nil
}

// TrustDomain returns the trust domain that the bundle belongs to.
func (b *Bundle) TrustDomain() spiffeid.TrustDomain {
	return b.trustDomain
}

// JWTAuthorities returns the JWT authorities in the bundle, keyed by key ID.
func (b *Bundle) JWTAuthorities() map[string]crypto.PublicKey {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return jwtutil.CopyJWTAuthorities(b.jwtAuthorities)
}

// FindJWTAuthority finds the JWT authority with the given key ID from the bundle. If the authority
// is found, it is returned and the boolean is true. Otherwise, the returned
// value is nil and the boolean is false.
func (b *Bundle) FindJWTAuthority(keyID string) (crypto.PublicKey, bool) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if jwtAuthority, ok := b.jwtAuthorities[keyID]; ok {
		return jwtAuthority, true
	}
	return nil, false
}

// HasJWTAuthority returns true if the bundle has a JWT authority with the given key ID.
func (b *Bundle) HasJWTAuthority(keyID string) bool {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	_, ok := b.jwtAuthorities[keyID]
	return ok
}

// AddJWTAuthority adds a JWT authority to the bundle. If a JWT authority already exists
// under the given key ID, it is replaced. A key ID must be specified and the
// authority must be an ML-DSA-65 public key.
func (b *Bundle) AddJWTAuthority(keyID string, jwtAuthority crypto.PublicKey) error {
	if keyID == "" {
		return wrapJwtbundleErr(errors.New("keyID cannot be empty"))
	}
	if err := validateAuthority(jwtAuthority); err != nil {
		return wrapJwtbundleErr(err)
	}

	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.jwtAuthorities[keyID] = jwtAuthority
	return nil
}

// RemoveJWTAuthority removes the JWT authority identified by the key ID from the bundle.
func (b *Bundle) RemoveJWTAuthority(keyID string) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	delete(b.jwtAuthorities, keyID)
}

// SetJWTAuthorities sets the JWT authorities in the bundle. Entries that are
// not ML-DSA-65 public keys are dropped.
func (b *Bundle) SetJWTAuthorities(jwtAuthorities map[string]crypto.PublicKey) {
	filtered := make(map[string]crypto.PublicKey, len(jwtAuthorities))
	for keyID, authority := range jwtAuthorities {
		if keyID != "" && validateAuthority(authority) == nil {
			filtered[keyID] = authority
		}
	}

	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.jwtAuthorities = filtered
}

// Empty returns true if the bundle has no JWT authorities.
func (b *Bundle) Empty() bool {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return len(b.jwtAuthorities) == 0
}

// Marshal marshals the JWT bundle into a standard RFC 7517 JWKS document. The
// JWKS does not contain any SPIFFE-specific parameters.
func (b *Bundle) Marshal() ([]byte, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	keys := make(map[string]*mldsa.PublicKey, len(b.jwtAuthorities))
	for keyID, authority := range b.jwtAuthorities {
		publicKey, ok := authority.(*mldsa.PublicKey)
		if !ok || validateAuthority(publicKey) != nil {
			return nil, wrapJwtbundleErr(fmt.Errorf("authority %q is not an ML-DSA-65 public key", keyID))
		}
		keys[keyID] = publicKey
	}

	marshaled, err := pqjose.MarshalJWKS(keys)
	if err != nil {
		return nil, wrapJwtbundleErr(err)
	}
	return marshaled, nil
}

// Clone clones the bundle.
func (b *Bundle) Clone() *Bundle {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return FromJWTAuthorities(b.trustDomain, b.jwtAuthorities)
}

// Equal compares the bundle for equality against the given bundle.
func (b *Bundle) Equal(other *Bundle) bool {
	if b == nil || other == nil {
		return b == other
	}

	return b.trustDomain == other.trustDomain &&
		jwtutil.JWTAuthoritiesEqual(b.jwtAuthorities, other.jwtAuthorities)
}

// GetJWTBundleForTrustDomain returns the JWT bundle for the given trust
// domain. It implements the Source interface. An error will be returned if
// the trust domain does not match that of the bundle.
func (b *Bundle) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if b.trustDomain != trustDomain {
		return nil, wrapJwtbundleErr(fmt.Errorf("no JWT bundle for trust domain %q", trustDomain))
	}

	return b, nil
}

func validateAuthority(jwtAuthority crypto.PublicKey) error {
	publicKey, ok := jwtAuthority.(*mldsa.PublicKey)
	if !ok {
		return fmt.Errorf("unsupported JWT authority key type %T", jwtAuthority)
	}
	if publicKey == nil || len(publicKey.Bytes()) != mldsa.MLDSA65().PublicKeySize() ||
		publicKey.Parameters() != mldsa.MLDSA65() {
		return errors.New("JWT authority is not an ML-DSA-65 public key")
	}
	return nil
}

func wrapJwtbundleErr(err error) error {
	return fmt.Errorf("jwtbundle: %w", err)
}
