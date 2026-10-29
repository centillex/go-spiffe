package jwtbundle_test

import (
	"crypto"
	"crypto/mldsa"
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

var (
	td      = spiffeid.RequireTrustDomainFromString("domain.test")
	otherTD = spiffeid.RequireTrustDomainFromString("other.test")
)

func newKey(t *testing.T) *mldsa.PublicKey {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	return key.PublicKey()
}

func TestAuthoritiesCRUD(t *testing.T) {
	bundle := jwtbundle.New(td)
	require.True(t, bundle.Empty())
	require.Equal(t, td, bundle.TrustDomain())

	key := newKey(t)
	require.NoError(t, bundle.AddJWTAuthority("KEY", key))
	require.False(t, bundle.Empty())
	require.True(t, bundle.HasJWTAuthority("KEY"))

	found, ok := bundle.FindJWTAuthority("KEY")
	require.True(t, ok)
	require.True(t, found.(*mldsa.PublicKey).Equal(key))

	require.Error(t, bundle.AddJWTAuthority("", key))
	require.Error(t, bundle.AddJWTAuthority("EC", nil))

	bundle.RemoveJWTAuthority("KEY")
	require.True(t, bundle.Empty())
	_, ok = bundle.FindJWTAuthority("KEY")
	require.False(t, ok)
}

func TestSetDropsUnsupportedAuthorities(t *testing.T) {
	bundle := jwtbundle.New(td)
	key := newKey(t)
	bundle.SetJWTAuthorities(map[string]crypto.PublicKey{
		"HOME":      key,
		"CLASSICAL": nil,
		"":          key,
	})
	require.Len(t, bundle.JWTAuthorities(), 1)
	require.True(t, bundle.HasJWTAuthority("HOME"))
}

func TestParseMarshalRoundTrip(t *testing.T) {
	bundle := jwtbundle.New(td)
	keyA, keyB := newKey(t), newKey(t)
	require.NoError(t, bundle.AddJWTAuthority("A", keyA))
	require.NoError(t, bundle.AddJWTAuthority("B", keyB))

	encoded, err := bundle.Marshal()
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"kty":"AKP"`)
	require.Contains(t, string(encoded), `"alg":"ML-DSA-65"`)
	require.NotContains(t, string(encoded), `"priv"`)

	parsed, err := jwtbundle.Parse(td, encoded)
	require.NoError(t, err)
	require.True(t, bundle.Equal(parsed))
	require.True(t, findAuthority(t, parsed, "A").Equal(keyA))
	require.True(t, findAuthority(t, parsed, "B").Equal(keyB))
}

func TestParseRejectsClassicalAndPrivateEntries(t *testing.T) {
	_, err := jwtbundle.Parse(td, []byte(`{"keys":[{"kty":"EC","kid":"KEY","crv":"P-256","x":"AA","y":"AA"}]}`))
	require.ErrorContains(t, err, "unsupported key type")

	_, err = jwtbundle.Parse(td, []byte(`{"keys":[{"kty":"AKP","alg":"ML-DSA-65","kid":"KEY","pub":"AA","priv":"AA"}]}`))
	require.ErrorContains(t, err, "private material")

	_, err = jwtbundle.Parse(td, []byte(`{"keys":[]}`))
	require.ErrorContains(t, err, "no keys")
}

func TestCloneEqualAndTrustDomain(t *testing.T) {
	bundle := jwtbundle.New(td)
	key := newKey(t)
	require.NoError(t, bundle.AddJWTAuthority("KEY", key))
	clone := bundle.Clone()
	require.True(t, bundle.Equal(clone))
	require.False(t, bundle.Equal(jwtbundle.New(td)))
	require.False(t, bundle.Equal(jwtbundle.New(otherTD)))
	require.False(t, bundle.Equal(nil))

	clone.RemoveJWTAuthority("KEY")
	require.True(t, bundle.HasJWTAuthority("KEY"))

	got, err := bundle.GetJWTBundleForTrustDomain(td)
	require.NoError(t, err)
	require.Same(t, bundle, got)
	_, err = bundle.GetJWTBundleForTrustDomain(otherTD)
	require.ErrorContains(t, err, "no JWT bundle")
}

func TestMarshalEmptyBundle(t *testing.T) {
	encoded, err := jwtbundle.New(td).Marshal()
	require.NoError(t, err)
	require.JSONEq(t, `{"keys":[]}`, string(encoded))
}

func TestLoadAndRead(t *testing.T) {
	bundle := jwtbundle.New(td)
	require.NoError(t, bundle.AddJWTAuthority("KEY", newKey(t)))
	encoded, err := bundle.Marshal()
	require.NoError(t, err)

	read, err := jwtbundle.Read(td, strings.NewReader(string(encoded)))
	require.NoError(t, err)
	require.True(t, bundle.Equal(read))
}

func findAuthority(t *testing.T, bundle *jwtbundle.Bundle, keyID string) *mldsa.PublicKey {
	t.Helper()
	authority, ok := bundle.FindJWTAuthority(keyID)
	require.True(t, ok)
	publicKey, ok := authority.(*mldsa.PublicKey)
	require.True(t, ok)
	return publicKey
}
