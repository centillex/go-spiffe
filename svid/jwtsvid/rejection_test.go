package jwtsvid_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/stretchr/testify/require"
)

// TestTokenOperationsAreUnsupported pins the strict-profile boundary for
// JWT-SVID parsing and validation. Insecure parsing is rejected as well, so a
// caller cannot obtain claims without signature verification.
func TestTokenOperationsAreUnsupported(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	// Shaped like a compact JWS; parsing must reject before inspection.
	token := "eyJhbGciOiJFUzI1NiJ9" + "." + "eyJzdWIiOiJzcGlmZmU6Ly9kb21haW4udGVzdC93b3JrbG9hZCJ9" + ".c2ln"

	svid, err := jwtsvid.ParseAndValidate(token, jwtbundle.NewSet(jwtbundle.New(td)), []string{"audience"})
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
	require.Nil(t, svid)

	svid, err = jwtsvid.ParseInsecure(token, []string{"audience"})
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
	require.Nil(t, svid)
}
