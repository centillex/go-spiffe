package pqjose

import (
	"crypto/mldsa"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	return key
}

func TestSignAndVerify(t *testing.T) {
	key := testKey(t)
	token, err := SignJWT("key-1", []byte(`{"sub":"spiffe://example.org/workload"}`), key)
	require.NoError(t, err)

	parsed, err := ParseJWT(token)
	require.NoError(t, err)
	require.Equal(t, Header{Algorithm: "ML-DSA-65", KeyID: "key-1", Type: "JWT"}, parsed.Header())
	require.JSONEq(t, `{"sub":"spiffe://example.org/workload"}`, string(parsed.Claims()))
	require.NoError(t, parsed.Verify(key.PublicKey()))
}

func TestVerifyRejectsTampering(t *testing.T) {
	key := testKey(t)
	token, err := SignJWT("key-1", []byte(`{"sub":"spiffe://example.org/workload"}`), key)
	require.NoError(t, err)
	parts := strings.Split(token, ".")

	for name, mutate := range map[string]func([]string){
		"payload": func(p []string) { p[1] = b64.EncodeToString([]byte(`{"sub":"spiffe://example.org/other"}`)) },
		"signature": func(p []string) {
			sig, err := b64.DecodeString(p[2])
			require.NoError(t, err)
			sig[0] ^= 0x01
			p[2] = b64.EncodeToString(sig)
		},
		"header": func(p []string) { p[0] = b64.EncodeToString([]byte(`{"alg":"ML-DSA-65","kid":"key-2","typ":"JWT"}`)) },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := append([]string(nil), parts...)
			mutate(tampered)
			parsed, err := ParseJWT(strings.Join(tampered, "."))
			require.NoError(t, err)
			require.Error(t, parsed.Verify(key.PublicKey()))
		})
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	token, err := SignJWT("key-1", []byte(`{}`), testKey(t))
	require.NoError(t, err)
	parsed, err := ParseJWT(token)
	require.NoError(t, err)
	require.Error(t, parsed.Verify(testKey(t).PublicKey()))
}

func TestParseRejectsClassicalAndInsecureAlgorithms(t *testing.T) {
	payload := b64.EncodeToString([]byte(`{}`))
	for name, header := range map[string]string{
		"none":      `{"alg":"none"}`,
		"HS256":     `{"alg":"HS256"}`,
		"ES256":     `{"alg":"ES256"}`,
		"ML-DSA-44": `{"alg":"ML-DSA-44"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseJWT(b64.EncodeToString([]byte(header)) + "." + payload + "." + b64.EncodeToString(make([]byte, mldsa.MLDSA65().SignatureSize())))
			require.ErrorContains(t, err, "unsupported algorithm")
		})
	}
}

func TestParseRejectsBadTokenType(t *testing.T) {
	payload := b64.EncodeToString([]byte(`{}`))
	header := b64.EncodeToString([]byte(`{"alg":"ML-DSA-65","typ":"at+jwt"}`))
	_, err := ParseJWT(header + "." + payload + "." + b64.EncodeToString(make([]byte, mldsa.MLDSA65().SignatureSize())))
	require.ErrorContains(t, err, "unsupported token type")
}

func TestPublicJWKRoundTrip(t *testing.T) {
	key := testKey(t)
	encoded, err := MarshalPublicJWK("key-1", key.PublicKey())
	require.NoError(t, err)

	var jwk JWK
	require.NoError(t, json.Unmarshal(encoded, &jwk))
	require.Equal(t, "AKP", jwk.KeyType)
	require.Equal(t, "ML-DSA-65", jwk.Algorithm)
	require.Empty(t, jwk.Private)

	keyID, publicKey, err := ParsePublicJWK(encoded)
	require.NoError(t, err)
	require.Equal(t, "key-1", keyID)
	require.True(t, publicKey.Equal(key.PublicKey()))
}

func TestPublicJWKRejectsPrivateMaterial(t *testing.T) {
	key := testKey(t)
	encoded, err := MarshalPrivateJWK("key-1", key)
	require.NoError(t, err)
	_, _, err = ParsePublicJWK(encoded)
	require.ErrorContains(t, err, "private material")
}

func TestPrivateJWKRoundTrip(t *testing.T) {
	key := testKey(t)
	encoded, err := MarshalPrivateJWK("key-1", key)
	require.NoError(t, err)
	keyID, parsed, err := ParsePrivateJWK(encoded)
	require.NoError(t, err)
	require.Equal(t, "key-1", keyID)
	require.True(t, parsed.PublicKey().Equal(key.PublicKey()))

	token, err := SignJWT(keyID, []byte(`{}`), parsed)
	require.NoError(t, err)
	require.NoError(t, mustParse(t, token).Verify(key.PublicKey()))
}

func TestPrivateJWKRejectsMismatchedPublicKey(t *testing.T) {
	key := testKey(t)
	encoded, err := MarshalPrivateJWK("key-1", key)
	require.NoError(t, err)
	other, err := MarshalPublicJWK("key-1", testKey(t).PublicKey())
	require.NoError(t, err)
	var jwk, otherJWK JWK
	require.NoError(t, json.Unmarshal(encoded, &jwk))
	require.NoError(t, json.Unmarshal(other, &otherJWK))
	jwk.Public = otherJWK.Public
	mismatched, err := json.Marshal(jwk)
	require.NoError(t, err)
	_, _, err = ParsePrivateJWK(mismatched)
	require.ErrorContains(t, err, "does not match private seed")
}

func TestJWKSRoundTrip(t *testing.T) {
	keys := map[string]*mldsa.PublicKey{
		"b": testKey(t).PublicKey(),
		"a": testKey(t).PublicKey(),
	}
	encoded, err := MarshalJWKS(keys)
	require.NoError(t, err)
	parsed, err := ParseJWKS(encoded)
	require.NoError(t, err)
	require.Len(t, parsed, 2)
	require.True(t, parsed["a"].Equal(keys["a"]))
	require.True(t, parsed["b"].Equal(keys["b"]))

	// Deterministic output: the order is sorted by key ID.
	first := strings.Index(string(encoded), `"kid":"a"`)
	second := strings.Index(string(encoded), `"kid":"b"`)
	require.Less(t, first, second)
}

func TestJWKSRejectsDuplicateKeyIDs(t *testing.T) {
	key := testKey(t)
	first, err := MarshalPublicJWK("dup", key.PublicKey())
	require.NoError(t, err)
	_, err = ParseJWKS([]byte(`{"keys":[` + string(first) + `,` + string(first) + `]}`))
	require.ErrorContains(t, err, "duplicate key ID")
}

func TestJWKSRejectsClassicalEntries(t *testing.T) {
	_, err := ParseJWKS([]byte(`{"keys":[{"kty":"EC","kid":"k","crv":"P-256","x":"AA","y":"AA"}]}`))
	require.ErrorContains(t, err, "unsupported key type")
}

func TestThumbprint(t *testing.T) {
	key := testKey(t)
	thumbprint, err := Thumbprint(key.PublicKey())
	require.NoError(t, err)
	require.NotEmpty(t, thumbprint)
	again, err := Thumbprint(key.PublicKey())
	require.NoError(t, err)
	require.Equal(t, thumbprint, again)
	_, err = Thumbprint(testKey(t).PublicKey())
	require.NoError(t, err)
}

func mustParse(t *testing.T, token string) *Token {
	t.Helper()
	parsed, err := ParseJWT(token)
	require.NoError(t, err)
	return parsed
}
