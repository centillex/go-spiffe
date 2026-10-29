package jwtsvid

import (
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
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
func ParseAndValidate(token string, bundles jwtbundle.Source, audience []string) (*SVID, error) {
	return nil, pqprofile.Unsupported("jwtsvid.ParseAndValidate")
}

// ParseInsecure parses and validates a JWT-SVID token and returns the
// JWT-SVID. The JWT-SVID signature is not verified.
func ParseInsecure(token string, audience []string) (*SVID, error) {
	return nil, pqprofile.Unsupported("jwtsvid.ParseInsecure")
}

// Marshal returns the JWT-SVID marshaled to a string. The returned value is
// the same token value originally passed to ParseAndValidate.
func (svid *SVID) Marshal() string {
	return svid.token
}
