package spiffebundle

import (
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"

	"github.com/spiffe/go-spiffe/v2/internal/jwtutil"
	"github.com/spiffe/go-spiffe/v2/internal/x509util"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	x509SVIDUse = "x509-svid"
	jwtSVIDUse  = "jwt-svid"
	witSVIDUse  = "wit-svid"
)

// Bundle is a collection of trusted public key material for a trust domain,
// conforming to the SPIFFE Bundle Format as part of the SPIFFE Trust Domain
// and Bundle specification:
// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md
type Bundle struct {
	trustDomain spiffeid.TrustDomain

	mtx             sync.RWMutex
	refreshHint     *time.Duration
	sequenceNumber  *uint64
	jwtAuthorities  map[string]crypto.PublicKey
	witAuthorities  map[string]crypto.PublicKey
	x509Authorities []*x509.Certificate
}

// New creates a new bundle.
func New(trustDomain spiffeid.TrustDomain) *Bundle {
	return &Bundle{
		trustDomain:    trustDomain,
		jwtAuthorities: make(map[string]crypto.PublicKey),
		witAuthorities: make(map[string]crypto.PublicKey),
	}
}

// Load loads a bundle from a file on disk. The file must contain a JWKS
// document following the SPIFFE Trust Domain and Bundle specification.
func Load(trustDomain spiffeid.TrustDomain, path string) (*Bundle, error) {
	bundleBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, wrapSpiffebundleErr(fmt.Errorf("unable to read SPIFFE bundle: %w", err))
	}

	return Parse(trustDomain, bundleBytes)
}

// Read decodes a bundle from a reader. The contents must contain a JWKS
// document following the SPIFFE Trust Domain and Bundle specification.
func Read(trustDomain spiffeid.TrustDomain, r io.Reader) (*Bundle, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, wrapSpiffebundleErr(fmt.Errorf("unable to read: %v", err))
	}

	return Parse(trustDomain, b)
}

// Parse parses a bundle from bytes. The data must be a JWKS document following
// the SPIFFE Trust Domain and Bundle specification. This general data reader
// retains legacy token/classical capability; use ParseX509Only for strict-profile
// X.509 trust admission. Decoding alone does not authenticate provisioning.
func Parse(trustDomain spiffeid.TrustDomain, bundleBytes []byte) (*Bundle, error) {
	return parseDocument(trustDomain, bundleBytes, false)
}

// FromX509Bundle creates a bundle from an X.509 bundle.
// The function panics in case of a nil X.509 bundle.
func FromX509Bundle(x509Bundle *x509bundle.Bundle) *Bundle {
	bundle := New(x509Bundle.TrustDomain())
	bundle.x509Authorities = x509Bundle.X509Authorities()
	return bundle
}

// FromJWTBundle creates a bundle from a JWT bundle.
func FromJWTBundle(jwtBundle *jwtbundle.Bundle) *Bundle {
	bundle := New(jwtBundle.TrustDomain())
	bundle.SetJWTAuthorities(jwtBundle.JWTAuthorities())
	return bundle
}

// FromX509Authorities creates a bundle from X.509 certificates.
func FromX509Authorities(trustDomain spiffeid.TrustDomain, x509Authorities []*x509.Certificate) *Bundle {
	bundle := New(trustDomain)
	bundle.x509Authorities = x509util.CopyX509Authorities(x509Authorities)
	return bundle
}

// FromJWTAuthorities creates a bundle from JWT authorities. Authorities that
// are not ML-DSA-65 public keys are dropped.
func FromJWTAuthorities(trustDomain spiffeid.TrustDomain, jwtAuthorities map[string]crypto.PublicKey) *Bundle {
	bundle := New(trustDomain)
	bundle.SetJWTAuthorities(jwtAuthorities)
	return bundle
}

// FromWITAuthorities returns an empty bundle. WIT authorities are outside the
// strict profile and are never admitted.
func FromWITAuthorities(trustDomain spiffeid.TrustDomain, witAuthorities map[string]crypto.PublicKey) *Bundle {
	return New(trustDomain)
}

// FromWITBundle returns an empty bundle for the WIT bundle's trust domain.
// WIT authorities are outside the strict profile and are never admitted.
func FromWITBundle(witBundle *witbundle.Bundle) *Bundle {
	return New(witBundle.TrustDomain())
}

// TrustDomain returns the trust domain that the bundle belongs to.
func (b *Bundle) TrustDomain() spiffeid.TrustDomain {
	return b.trustDomain
}

// X509Authorities returns the X.509 authorities in the bundle.
func (b *Bundle) X509Authorities() []*x509.Certificate {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return x509util.CopyX509Authorities(b.x509Authorities)
}

// AddX509Authority adds an X.509 authority to the bundle. If the authority already
// exists in the bundle, the contents of the bundle will remain unchanged.
func (b *Bundle) AddX509Authority(x509Authority *x509.Certificate) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	for _, r := range b.x509Authorities {
		if x509util.CertificatesEqual(r, x509Authority) {
			return
		}
	}

	b.x509Authorities = append(b.x509Authorities, x509util.CopyX509Authority(x509Authority))
}

// RemoveX509Authority removes an X.509 authority from the bundle.
func (b *Bundle) RemoveX509Authority(x509Authority *x509.Certificate) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	for i, r := range b.x509Authorities {
		if x509util.CertificatesEqual(r, x509Authority) {
			b.x509Authorities = append(b.x509Authorities[:i], b.x509Authorities[i+1:]...)
			return
		}
	}
}

// HasX509Authority checks if the given X.509 authority exists in the bundle.
func (b *Bundle) HasX509Authority(x509Authority *x509.Certificate) bool {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	for _, r := range b.x509Authorities {
		if x509util.CertificatesEqual(r, x509Authority) {
			return true
		}
	}
	return false
}

// SetX509Authorities sets the X.509 authorities in the bundle.
func (b *Bundle) SetX509Authorities(authorities []*x509.Certificate) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.x509Authorities = x509util.CopyX509Authorities(authorities)
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

	authority, ok := b.jwtAuthorities[keyID]
	return authority, ok
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
		return wrapSpiffebundleErr(errors.New("keyID cannot be empty"))
	}
	if err := validateJWTAuthority(jwtAuthority); err != nil {
		return wrapSpiffebundleErr(err)
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
		if keyID != "" && validateJWTAuthority(authority) == nil {
			filtered[keyID] = authority
		}
	}

	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.jwtAuthorities = filtered
}

// WITAuthorities returns the WIT authorities in the bundle, keyed by key ID.
func (b *Bundle) WITAuthorities() map[string]crypto.PublicKey {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return jwtutil.CopyJWTAuthorities(b.witAuthorities)
}

// FindWITAuthority finds the WIT authority with the given key ID from the bundle.
// If the authority is found, it is returned and the boolean is true. Otherwise,
// the returned value is nil and the boolean is false.
func (b *Bundle) FindWITAuthority(keyID string) (crypto.PublicKey, bool) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	witAuthority, ok := b.witAuthorities[keyID]
	return witAuthority, ok
}

// HasWITAuthority returns true if the bundle has a WIT authority with the given key ID.
func (b *Bundle) HasWITAuthority(keyID string) bool {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	_, ok := b.witAuthorities[keyID]
	return ok
}

// AddWITAuthority adds a WIT authority to the bundle. If a WIT authority already exists
// under the given key ID, it is replaced. A key ID must be specified.
func (b *Bundle) AddWITAuthority(keyID string, witAuthority crypto.PublicKey) error {
	return pqprofile.Unsupported("spiffebundle.AddWITAuthority")
}

// RemoveWITAuthority removes the WIT authority identified by the key ID from the bundle.
func (b *Bundle) RemoveWITAuthority(keyID string) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	delete(b.witAuthorities, keyID)
}

// SetWITAuthorities sets the WIT authorities in the bundle.
func (b *Bundle) SetWITAuthorities(witAuthorities map[string]crypto.PublicKey) {
	// Authorities are never admitted under the strict profile.
}

// Empty returns true if the bundle has no X.509, JWT, or WIT authorities.
func (b *Bundle) Empty() bool {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return len(b.x509Authorities) == 0 && len(b.jwtAuthorities) == 0 && len(b.witAuthorities) == 0
}

// RefreshHint returns the refresh hint. If the refresh hint is set in
// the bundle, it is returned and the boolean is true. Otherwise, the returned
// value is zero and the boolean is false.
func (b *Bundle) RefreshHint() (refreshHint time.Duration, ok bool) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if b.refreshHint != nil {
		return *b.refreshHint, true
	}
	return 0, false
}

// SetRefreshHint sets the refresh hint. The refresh hint value will be
// truncated to time.Second.
func (b *Bundle) SetRefreshHint(refreshHint time.Duration) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.refreshHint = &refreshHint
}

// ClearRefreshHint clears the refresh hint.
func (b *Bundle) ClearRefreshHint() {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.refreshHint = nil
}

// SequenceNumber returns the sequence number. If the sequence number is set in
// the bundle, it is returned and the boolean is true. Otherwise, the returned
// value is zero and the boolean is false.
func (b *Bundle) SequenceNumber() (uint64, bool) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if b.sequenceNumber != nil {
		return *b.sequenceNumber, true
	}
	return 0, false
}

// SetSequenceNumber sets the sequence number.
func (b *Bundle) SetSequenceNumber(sequenceNumber uint64) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.sequenceNumber = &sequenceNumber
}

// ClearSequenceNumber clears the sequence number.
func (b *Bundle) ClearSequenceNumber() {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.sequenceNumber = nil
}

// Marshal marshals the bundle according to the SPIFFE Trust Domain and Bundle
// specification. The trust domain is not marshaled as part of the bundle and
// must be conveyed separately. See the specification for details.
func (b *Bundle) Marshal() ([]byte, error) {
	return b.marshalDocument()
}

// Clone clones the bundle.
func (b *Bundle) Clone() *Bundle {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return &Bundle{
		trustDomain:     b.trustDomain,
		refreshHint:     copyRefreshHint(b.refreshHint),
		sequenceNumber:  copySequenceNumber(b.sequenceNumber),
		x509Authorities: x509util.CopyX509Authorities(b.x509Authorities),
		jwtAuthorities:  jwtutil.CopyJWTAuthorities(b.jwtAuthorities),
		witAuthorities:  jwtutil.CopyJWTAuthorities(b.witAuthorities),
	}
}

// X509Bundle returns an X.509 bundle containing the X.509 authorities in the SPIFFE
// bundle.
func (b *Bundle) X509Bundle() *x509bundle.Bundle {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	// FromX509Authorities makes a copy, so we can pass our internal slice directly.
	return x509bundle.FromX509Authorities(b.trustDomain, b.x509Authorities)
}

// JWTBundle returns a JWT bundle containing the JWT authorities in the SPIFFE bundle.
func (b *Bundle) JWTBundle() *jwtbundle.Bundle {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	// FromJWTBundle makes a copy, so we can pass our internal slice directly.
	return jwtbundle.FromJWTAuthorities(b.trustDomain, b.jwtAuthorities)
}

// GetBundleForTrustDomain returns the SPIFFE bundle for the given trust
// domain. It implements the Source interface. An error will be returned if the
// trust domain does not match that of the bundle.
func (b *Bundle) GetBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if b.trustDomain != trustDomain {
		return nil, wrapSpiffebundleErr(fmt.Errorf("no SPIFFE bundle for trust domain %q", trustDomain))
	}

	return b, nil
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain. It implements the x509bundle.Source interface. An error will be
// returned if the trust domain does not match that of the bundle.
func (b *Bundle) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if b.trustDomain != trustDomain {
		return nil, wrapSpiffebundleErr(fmt.Errorf("no X.509 bundle for trust domain %q", trustDomain))
	}

	return b.X509Bundle(), nil
}

// GetJWTBundleForTrustDomain returns the JWT bundle of the given trust domain.
// It implements the jwtbundle.Source interface. An error will be returned if
// the trust domain does not match that of the bundle.
func (b *Bundle) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	if b.trustDomain != trustDomain {
		return nil, wrapSpiffebundleErr(fmt.Errorf("no JWT bundle for trust domain %q", trustDomain))
	}

	return b.JWTBundle(), nil
}

// WITBundle returns a WIT bundle containing the WIT authorities in the SPIFFE bundle.
func (b *Bundle) WITBundle() *witbundle.Bundle {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return witbundle.FromWITAuthorities(b.trustDomain, b.witAuthorities)
}

// GetWITBundleForTrustDomain returns the WIT bundle of the given trust domain.
// It implements the witbundle.Source interface. An error will be returned if
// the trust domain does not match that of the bundle.
func (b *Bundle) GetWITBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*witbundle.Bundle, error) {
	return nil, pqprofile.Unsupported("spiffebundle.GetWITBundleForTrustDomain")
}

// Equal compares the bundle for equality against the given bundle.
func (b *Bundle) Equal(other *Bundle) bool {
	if b == nil || other == nil {
		return b == other
	}

	if b == other {
		return true
	}
	b, other = b.Clone(), other.Clone()
	return b.trustDomain == other.trustDomain &&
		refreshHintEqual(b.refreshHint, other.refreshHint) &&
		sequenceNumberEqual(b.sequenceNumber, other.sequenceNumber) &&
		jwtutil.JWTAuthoritiesEqual(b.jwtAuthorities, other.jwtAuthorities) &&
		jwtutil.JWTAuthoritiesEqual(b.witAuthorities, other.witAuthorities) &&
		x509util.CertsEqual(b.x509Authorities, other.x509Authorities)
}

func refreshHintEqual(a, b *time.Duration) bool {
	if a == nil || b == nil {
		return a == b
	}

	return *a == *b
}

func sequenceNumberEqual(a, b *uint64) bool {
	if a == nil || b == nil {
		return a == b
	}

	return *a == *b
}

func copyRefreshHint(refreshHint *time.Duration) *time.Duration {
	if refreshHint == nil {
		return nil
	}
	copied := *refreshHint
	return &copied
}

func copySequenceNumber(sequenceNumber *uint64) *uint64 {
	if sequenceNumber == nil {
		return nil
	}
	copied := *sequenceNumber
	return &copied
}

func validateJWTAuthority(jwtAuthority crypto.PublicKey) error {
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

func wrapSpiffebundleErr(err error) error {
	return fmt.Errorf("spiffebundle: %w", err)
}
