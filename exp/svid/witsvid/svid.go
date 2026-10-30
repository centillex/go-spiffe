// Package witsvid provides support for WIT-SVIDs (Workload Identity Token
// SVIDs), an experimental SPIFFE credential type based on the IETF WIMSE WIT
// specification. WIT-SVIDs bind a public key to the workload identity via the
// cnf.jwk claim and are never bearer tokens.
package witsvid

import (
	"crypto/mldsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/pqjose"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	tokenType = "wit+jwt"
	// Leeway matches JWT-SVID clock-skew handling.
	leeway = 30 * time.Second
)

// SVID represents a WIT-SVID.
type SVID struct {
	// ID is the SPIFFE ID of the WIT-SVID as present in the 'sub' claim.
	ID spiffeid.ID
	// Expiry is the expiration time of the WIT-SVID as present in the 'exp' claim.
	Expiry time.Time
	// PublicKey is the public key bound to the WIT-SVID via the cnf.jwk claim.
	PublicKey *mldsa.PublicKey
	// KeyID is the key ID from the JOSE header.
	KeyID string
	// PrivateKey is the private key corresponding to PublicKey. It is populated
	// when the WIT-SVID is fetched from the Workload API, and nil otherwise.
	PrivateKey *mldsa.PrivateKey
	// Hint is an operator-specified string used to provide guidance on how this
	// identity should be used by a workload when more than one SVID is returned.
	Hint string

	token string
}

// Marshal returns the WIT-SVID as a JWS compact serialization string.
func (s *SVID) Marshal() string {
	return s.token
}

// ParseAndValidate parses and validates a WIT-SVID token, verifying its
// signature using the provided WIT bundle source.
func ParseAndValidate(token string, bundles witbundle.Source) (*SVID, error) {
	return parse(token, func(tok *pqjose.Token, trustDomain spiffeid.TrustDomain, keyID string) error {
		bundle, err := bundles.GetWITBundleForTrustDomain(trustDomain)
		if err != nil {
			return wrapErr(fmt.Errorf("no WIT bundle found for trust domain %q", trustDomain))
		}
		authority, ok := bundle.FindWITAuthority(keyID)
		if !ok {
			return wrapErr(fmt.Errorf("no WIT authority %q found for trust domain %q", keyID, trustDomain))
		}
		publicKey, ok := authority.(*mldsa.PublicKey)
		if !ok {
			return wrapErr(fmt.Errorf("WIT authority %q is not an ML-DSA-65 public key", keyID))
		}
		if err := tok.Verify(publicKey); err != nil {
			return wrapErr(fmt.Errorf("signature verification failed: %w", err))
		}
		return nil
	})
}

// ParseInsecure parses a WIT-SVID token without verifying its signature. It
// should only be used when the token came from a trusted source such as the
// Workload API.
func ParseInsecure(token string) (*SVID, error) {
	return parse(token, func(*pqjose.Token, spiffeid.TrustDomain, string) error { return nil })
}

type verifyFn func(*pqjose.Token, spiffeid.TrustDomain, string) error

type claims struct {
	Subject   string         `json:"sub"`
	Audience  []string       `json:"aud"`
	Expiry    *numericDate   `json:"exp"`
	NotBefore *numericDate   `json:"nbf"`
	CNF       map[string]any `json:"cnf"`
}

type numericDate float64

func (n *numericDate) UnmarshalJSON(data []byte) error {
	var value float64
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("claim must be a numeric date")
	}
	*n = numericDate(value)
	return nil
}

func (n numericDate) Time() time.Time {
	seconds := int64(n)
	nanos := int64((float64(n) - float64(seconds)) * 1e9)
	return time.Unix(seconds, nanos)
}

func parse(token string, verify verifyFn) (*SVID, error) {
	tok, err := pqjose.ParseJWTWithTypes(token, tokenType)
	if err != nil {
		return nil, wrapErr(fmt.Errorf("unable to parse WIT-SVID token: %w", err))
	}
	keyID := tok.Header().KeyID
	if keyID == "" {
		return nil, wrapErr(errors.New("token header missing key id"))
	}

	var parsed claims
	if err := json.Unmarshal(tok.Claims(), &parsed); err != nil {
		return nil, wrapErr(fmt.Errorf("unable to parse claims: %w", err))
	}
	switch {
	case parsed.Subject == "":
		return nil, wrapErr(errors.New("token missing subject claim"))
	case parsed.Expiry == nil:
		return nil, wrapErr(errors.New("token missing exp claim"))
	case len(parsed.Audience) > 0:
		return nil, wrapErr(errors.New("WIT-SVID must not contain aud claim"))
	}
	spiffeID, err := spiffeid.FromString(parsed.Subject)
	if err != nil {
		return nil, wrapErr(fmt.Errorf("token has an invalid subject claim: %v", err))
	}

	publicKey, err := extractCNFKey(parsed.CNF)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	if !parsed.Expiry.Time().Add(leeway).After(now) {
		return nil, wrapErr(errors.New("token has expired"))
	}
	if parsed.NotBefore != nil && parsed.NotBefore.Time().After(now.Add(leeway)) {
		return nil, wrapErr(errors.New("token is not yet valid"))
	}

	if err := verify(tok, spiffeID.TrustDomain(), keyID); err != nil {
		return nil, err
	}

	return &SVID{
		ID:        spiffeID,
		Expiry:    parsed.Expiry.Time().UTC(),
		PublicKey: publicKey,
		KeyID:     keyID,
		token:     token,
	}, nil
}

func extractCNFKey(cnf map[string]any) (*mldsa.PublicKey, error) {
	if cnf == nil {
		return nil, wrapErr(errors.New("token missing cnf claim"))
	}
	jwkRaw, ok := cnf["jwk"]
	if !ok {
		return nil, wrapErr(errors.New("cnf claim missing jwk field"))
	}
	data, err := json.Marshal(jwkRaw)
	if err != nil {
		return nil, wrapErr(fmt.Errorf("unable to marshal cnf.jwk: %v", err))
	}
	_, publicKey, err := pqjose.ParsePublicJWK(data)
	if err != nil {
		return nil, wrapErr(fmt.Errorf("unable to parse cnf.jwk: %w", err))
	}
	return publicKey, nil
}

func wrapErr(err error) error {
	return fmt.Errorf("witsvid: %w", err)
}
