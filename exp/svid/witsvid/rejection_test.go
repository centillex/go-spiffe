package witsvid_test

import (
	"crypto/mldsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/pqjose"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

func testSetup(t *testing.T) (spiffeid.ID, *mldsa.PrivateKey, *mldsa.PrivateKey, *witbundle.Set) {
	t.Helper()
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	id := spiffeid.RequireFromPath(td, "/workload")
	serverKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	workloadKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	bundle := witbundle.New(td)
	require.NoError(t, bundle.AddWITAuthority("wit-key", serverKey.PublicKey()))
	return id, serverKey, workloadKey, witbundle.NewSet(bundle)
}

func signWIT(t *testing.T, id spiffeid.ID, key *mldsa.PrivateKey, workloadKey *mldsa.PrivateKey, mutate func(map[string]any)) string {
	t.Helper()
	cnfJWK, err := pqjose.MarshalPublicJWK("workload-key", workloadKey.PublicKey())
	require.NoError(t, err)
	var cnf map[string]any
	require.NoError(t, json.Unmarshal(cnfJWK, &cnf))
	claims := map[string]any{
		"sub": id.String(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": cnf},
	}
	if mutate != nil {
		mutate(claims)
	}
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	token, err := pqjose.SignJWTWithType("wit+jwt", "wit-key", payload, key)
	require.NoError(t, err)
	return token
}

func TestParseAndValidate(t *testing.T) {
	id, serverKey, workloadKey, bundles := testSetup(t)
	token := signWIT(t, id, serverKey, workloadKey, nil)

	svid, err := witsvid.ParseAndValidate(token, bundles)
	require.NoError(t, err)
	require.Equal(t, id, svid.ID)
	require.True(t, svid.PublicKey.Equal(workloadKey.PublicKey()))
	require.Equal(t, "wit-key", svid.KeyID)
	require.Equal(t, token, svid.Marshal())

	insecure, err := witsvid.ParseInsecure(token)
	require.NoError(t, err)
	require.Equal(t, id, insecure.ID)
}

func TestRejections(t *testing.T) {
	id, serverKey, workloadKey, bundles := testSetup(t)

	for name, mutate := range map[string]func(map[string]any){
		"audience": func(c map[string]any) { c["aud"] = []string{"audience"} },
		"subject":  func(c map[string]any) { delete(c, "sub") },
		"expiry":   func(c map[string]any) { delete(c, "exp") },
		"cnf":      func(c map[string]any) { delete(c, "cnf") },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := witsvid.ParseInsecure(signWIT(t, id, serverKey, workloadKey, mutate))
			require.Error(t, err)
		})
	}

	token := signWIT(t, id, serverKey, workloadKey, nil)
	parts := strings.Split(token, ".")
	parts[2] = parts[2][:len(parts[2])-2] + "AA"
	_, err := witsvid.ParseAndValidate(strings.Join(parts, "."), bundles)
	require.ErrorContains(t, err, "signature verification failed")

	// A JWT-SVID type is not a WIT-SVID.
	jwtToken, err := pqjose.SignJWT("wit-key", []byte(`{"sub":"`+id.String()+`","exp":4102444800}`), serverKey)
	require.NoError(t, err)
	_, err = witsvid.ParseInsecure(jwtToken)
	require.ErrorContains(t, err, "unsupported token type")
}
