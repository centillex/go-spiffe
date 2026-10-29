// Package witsvid provides support for WIT-SVIDs (Workload Identity Token SVIDs),
// an experimental SPIFFE credential type based on the IETF WIMSE WIT specification.
// WIT-SVIDs bind a public key to the workload identity via the cnf.jwk claim and
// require proof of possession — they are never bearer tokens.
package witsvid

import (
	"crypto"
	"time"

	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// SVID represents a WIT-SVID.
type SVID struct {
	// ID is the SPIFFE ID of the WIT-SVID as present in the 'sub' claim.
	ID spiffeid.ID

	// Expiry is the expiration time of the WIT-SVID as present in the 'exp' claim.
	Expiry time.Time

	// PublicKey is the public key bound to the WIT-SVID via the cnf.jwk claim.
	PublicKey crypto.PublicKey

	// KeyID is the key ID from the JOSE header.
	KeyID string

	// PrivateKey is the private key corresponding to PublicKey. It is populated
	// when the WIT-SVID is fetched from the Workload API, and nil otherwise.
	PrivateKey crypto.PrivateKey

	// Hint is an operator-specified string used to provide guidance on how this
	// identity should be used by a workload when more than one SVID is returned.
	Hint string

	// token is the serialized JWS compact serialization.
	token string
}

// Marshal returns the WIT-SVID as a JWS compact serialization string.
func (s *SVID) Marshal() string {
	return s.token
}

// ParseAndValidate parses and validates a WIT-SVID token, verifying its
// signature using the provided WIT bundle source.
func ParseAndValidate(token string, bundles witbundle.Source) (*SVID, error) {
	return nil, pqprofile.Unsupported("witsvid.ParseAndValidate")
}

// ParseInsecure parses a WIT-SVID token without verifying its signature.
// This should only be used when the token was received from a trusted source
// (e.g., the Workload API).
func ParseInsecure(token string) (*SVID, error) {
	return nil, pqprofile.Unsupported("witsvid.ParseInsecure")
}

// extractCnfJWK extracts and parses the public key from the cnf.jwk claim.
