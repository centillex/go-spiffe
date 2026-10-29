package jwtsvid

import (
	"crypto/mldsa"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/pqjose"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// SVID represents a JWT-SVID.
type SVID struct {
	// ID is the SPIFFE ID of the JWT-SVID as present in the 'sub' claim
	ID spiffeid.ID
	// Audience is the intended recipients of JWT-SVID as present in the 'aud' claim
	Audience []string
	// Expiry is the expiration time of JWT-SVID as present in 'exp' claim
	Expiry time.Time
	// Claims is the parsed claims from token
	Claims map[string]any
	// Hint is an operator-specified string used to provide guidance on how this
	// identity should be used by a workload when more than one SVID is returned.
	Hint string

	// token is the serialized JWT token
	token string
}

// ParseAndValidate parses and validates a JWT-SVID token and returns the
// JWT-SVID. The JWT-SVID signature is verified using the JWT bundle source.
// Only ML-DSA-65 tokens are accepted.
func ParseAndValidate(token string, bundles jwtbundle.Source, audience []string) (*SVID, error) {
	return parse(token, audience, func(tok *pqjose.Token, trustDomain spiffeid.TrustDomain) error {
		keyID := tok.Header().KeyID
		if keyID == "" {
			return wrapJwtsvidErr(errors.New("token header missing key id"))
		}

		bundle, err := bundles.GetJWTBundleForTrustDomain(trustDomain)
		if err != nil {
			return wrapJwtsvidErr(fmt.Errorf("no bundle found for trust domain %q", trustDomain))
		}

		authority, ok := bundle.FindJWTAuthority(keyID)
		if !ok {
			return wrapJwtsvidErr(fmt.Errorf("no JWT authority %q found for trust domain %q", keyID, trustDomain))
		}
		publicKey, ok := authority.(*mldsa.PublicKey)
		if !ok {
			return wrapJwtsvidErr(fmt.Errorf("JWT authority %q is not an ML-DSA-65 public key", keyID))
		}
		if err := tok.Verify(publicKey); err != nil {
			return wrapJwtsvidErr(fmt.Errorf("unable to verify token signature: %w", err))
		}
		return nil
	})
}

// ParseInsecure parses a JWT-SVID token and returns the JWT-SVID. The
// JWT-SVID signature is not verified.
func ParseInsecure(token string, audience []string) (*SVID, error) {
	return parse(token, audience, func(*pqjose.Token, spiffeid.TrustDomain) error { return nil })
}

// Marshal returns the JWT-SVID marshaled to a string. The returned value is
// the same token value originally passed to ParseAndValidate.
func (svid *SVID) Marshal() string {
	return svid.token
}

func parse(token string, audience []string, verify func(*pqjose.Token, spiffeid.TrustDomain) error) (*SVID, error) {
	tok, err := pqjose.ParseJWT(token)
	if err != nil {
		return nil, wrapJwtsvidErr(fmt.Errorf("unable to parse JWT token: %w", err))
	}

	claims, claimsMap, err := parseClaims(tok.Claims())
	if err != nil {
		return nil, wrapJwtsvidErr(fmt.Errorf("unable to get claims from token: %w", err))
	}

	switch {
	case claims.Subject == "":
		return nil, wrapJwtsvidErr(errors.New("token missing subject claim"))
	case claims.Expiry == nil:
		return nil, wrapJwtsvidErr(errors.New("token missing exp claim"))
	}

	spiffeID, err := spiffeid.FromString(claims.Subject)
	if err != nil {
		return nil, wrapJwtsvidErr(fmt.Errorf("token has an invalid subject claim: %v", err))
	}

	if err := verify(tok, spiffeID.TrustDomain()); err != nil {
		return nil, err
	}

	now := time.Now()
	if !claims.Expiry.Time().After(now) {
		return nil, wrapJwtsvidErr(errors.New("token has expired"))
	}
	if claims.NotBefore != nil && claims.NotBefore.Time().After(now) {
		return nil, wrapJwtsvidErr(errors.New("token is not valid yet"))
	}
	if len(audience) > 0 && !slices.ContainsFunc(audience, func(expected string) bool {
		return slices.Contains(claims.Audience, expected)
	}) {
		return nil, wrapJwtsvidErr(fmt.Errorf("expected audience in %q (audience=%q)", audience, claims.Audience))
	}

	return &SVID{
		ID:       spiffeID,
		Audience: append([]string(nil), claims.Audience...),
		Expiry:   claims.Expiry.Time().UTC(),
		Claims:   claimsMap,
		token:    token,
	}, nil
}

type claims struct {
	Subject   string       `json:"sub"`
	Audience  audience     `json:"aud"`
	Expiry    *numericDate `json:"exp"`
	NotBefore *numericDate `json:"nbf"`
	IssuedAt  *numericDate `json:"iat"`
}

func parseClaims(raw []byte) (*claims, map[string]any, error) {
	var parsed claims
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, nil, err
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, nil, err
	}
	return &parsed, generic, nil
}

type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return errors.New("aud claim must be a string or array of strings")
	}
	*a = many
	return nil
}

// numericDate is a JWT NumericDate as defined by RFC 7519.
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

func wrapJwtsvidErr(err error) error {
	return fmt.Errorf("jwtsvid: %w", err)
}
