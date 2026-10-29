package witsvid_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

// TestTokenOperationsAreUnsupported pins the strict-profile boundary for
// WIT-SVID parsing and validation, including insecure parsing.
func TestTokenOperationsAreUnsupported(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	// Shaped like a compact JWS; parsing must reject before inspection.
	token := "eyJhbGciOiJFUzI1NiJ9" + "." + "eyJzdWIiOiJzcGlmZmU6Ly9kb21haW4udGVzdC93b3JrbG9hZCJ9" + ".c2ln"

	svid, err := witsvid.ParseAndValidate(token, witbundle.NewSet(witbundle.New(td)))
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
	require.Nil(t, svid)

	svid, err = witsvid.ParseInsecure(token)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
	require.Nil(t, svid)
}
