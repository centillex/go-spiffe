package jwtsvid_test

import (
	"crypto/mldsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/pqjose"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/stretchr/testify/require"
)

const (
	testKeyID = "jwt-key"
	audience  = "audience.test"
)

func testKey(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	return key
}

func testBundles(t *testing.T, key *mldsa.PrivateKey) *jwtbundle.Set {
	t.Helper()
	bundle := jwtbundle.New(spiffeid.RequireTrustDomainFromString("domain.test"))
	require.NoError(t, bundle.AddJWTAuthority(testKeyID, key.PublicKey()))
	return jwtbundle.NewSet(bundle)
}

func signToken(t *testing.T, key *mldsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	token, err := pqjose.SignJWT(testKeyID, payload, key)
	require.NoError(t, err)
	return token
}

func validClaims() map[string]any {
	return map[string]any{
		"sub": "spiffe://domain.test/workload",
		"aud": []string{audience},
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
}

func TestParseAndValidate(t *testing.T) {
	key := testKey(t)
	token := signToken(t, key, validClaims())

	svid, err := jwtsvid.ParseAndValidate(token, testBundles(t, key), []string{audience})
	require.NoError(t, err)
	require.Equal(t, "spiffe://domain.test/workload", svid.ID.String())
	require.Equal(t, []string{audience}, svid.Audience)
	require.WithinDuration(t, time.Now().Add(time.Hour), svid.Expiry, time.Minute)
	require.IsType(t, float64(0), svid.Claims["exp"])
	require.Equal(t, token, svid.Marshal())
}

func TestParseInsecure(t *testing.T) {
	key := testKey(t)
	token := signToken(t, key, validClaims())
	svid, err := jwtsvid.ParseInsecure(token, nil)
	require.NoError(t, err)
	require.Equal(t, "spiffe://domain.test/workload", svid.ID.String())
}

func TestParseAndValidateAudience(t *testing.T) {
	key := testKey(t)
	token := signToken(t, key, validClaims())
	_, err := jwtsvid.ParseAndValidate(token, testBundles(t, key), []string{"other"})
	require.ErrorContains(t, err, "expected audience")
}

func TestParseAndValidateExpiry(t *testing.T) {
	key := testKey(t)
	claims := validClaims()
	claims["exp"] = time.Now().Add(-time.Minute).Unix()
	token := signToken(t, key, claims)
	_, err := jwtsvid.ParseAndValidate(token, testBundles(t, key), []string{audience})
	require.ErrorContains(t, err, "token has expired")
}

func TestParseAndValidateNotBefore(t *testing.T) {
	key := testKey(t)
	claims := validClaims()
	claims["nbf"] = time.Now().Add(time.Hour).Unix()
	token := signToken(t, key, claims)
	_, err := jwtsvid.ParseAndValidate(token, testBundles(t, key), []string{audience})
	require.ErrorContains(t, err, "not valid yet")
}

func TestParseAndValidateMissingClaims(t *testing.T) {
	key := testKey(t)
	for name, mutation := range map[string]func(map[string]any){
		"subject": func(c map[string]any) { delete(c, "sub") },
		"expiry":  func(c map[string]any) { delete(c, "exp") },
	} {
		t.Run(name, func(t *testing.T) {
			claims := validClaims()
			mutation(claims)
			token := signToken(t, key, claims)
			_, err := jwtsvid.ParseAndValidate(token, testBundles(t, key), []string{audience})
			require.Error(t, err)
		})
	}
}

func TestParseAndValidateRejectsTampering(t *testing.T) {
	key := testKey(t)
	token := signToken(t, key, validClaims())
	parts := strings.Split(token, ".")
	payload, err := json.Marshal(map[string]any{
		"sub": "spiffe://domain.test/other",
		"aud": []string{audience},
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	parts[1] = base64RawURL(payload)
	_, err = jwtsvid.ParseAndValidate(strings.Join(parts, "."), testBundles(t, key), []string{audience})
	require.ErrorContains(t, err, "signature verification failed")
}

func TestParseAndValidateUnknownKey(t *testing.T) {
	key := testKey(t)
	token := signToken(t, key, validClaims())
	otherBundle := jwtbundle.New(spiffeid.RequireTrustDomainFromString("domain.test"))
	_, err := jwtsvid.ParseAndValidate(token, jwtbundle.NewSet(otherBundle), []string{audience})
	require.ErrorContains(t, err, "no JWT authority")
}

func TestParseRejectsClassicalToken(t *testing.T) {
	token := base64RawURL([]byte(`{"alg":"ES256"}`)) + "." + base64RawURL([]byte(`{}`)) + ".c2ln"
	_, err := jwtsvid.ParseInsecure(token, nil)
	require.ErrorContains(t, err, "unsupported algorithm")
}

func base64RawURL(data []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var out strings.Builder
	for i := 0; i < len(data); i += 3 {
		var chunk uint32
		n := len(data) - i
		chunk = uint32(data[i]) << 16
		if n > 1 {
			chunk |= uint32(data[i+1]) << 8
		}
		if n > 2 {
			chunk |= uint32(data[i+2])
		}
		out.WriteByte(alphabet[(chunk>>18)&0x3f])
		out.WriteByte(alphabet[(chunk>>12)&0x3f])
		if n > 1 {
			out.WriteByte(alphabet[(chunk>>6)&0x3f])
		}
		if n > 2 {
			out.WriteByte(alphabet[chunk&0x3f])
		}
	}
	return out.String()
}
