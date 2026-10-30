package witbundle_test

import (
	"crypto"
	"crypto/mldsa"
	"testing"

	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

var td = spiffeid.RequireTrustDomainFromString("domain.test")

func newKey(t *testing.T) *mldsa.PublicKey {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	return key.PublicKey()
}

func TestAuthoritiesCRUD(t *testing.T) {
	bundle := witbundle.New(td)
	key := newKey(t)
	require.NoError(t, bundle.AddWITAuthority("KEY", key))
	require.True(t, bundle.HasWITAuthority("KEY"))
	found, ok := bundle.FindWITAuthority("KEY")
	require.True(t, ok)
	require.True(t, found.(*mldsa.PublicKey).Equal(key))

	bundle.RemoveWITAuthority("KEY")
	require.True(t, bundle.Empty())

	require.Error(t, bundle.AddWITAuthority("", key))
	require.ErrorContains(t, bundle.AddWITAuthority("CLASSICAL", "not a key"), "unsupported WIT authority")
}

func TestParseMarshalRoundTrip(t *testing.T) {
	bundle := witbundle.New(td)
	key := newKey(t)
	require.NoError(t, bundle.AddWITAuthority("KEY", key))

	encoded, err := bundle.Marshal()
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"kty":"AKP"`)
	require.Contains(t, string(encoded), `"use":"wit-svid"`)
	require.NotContains(t, string(encoded), `"priv"`)

	parsed, err := witbundle.Parse(td, encoded)
	require.NoError(t, err)
	require.True(t, bundle.Equal(parsed))
}

func TestParseRejectsClassicalAndPrivateEntries(t *testing.T) {
	_, err := witbundle.Parse(td, []byte(`{"keys":[{"kty":"EC","kid":"KEY","crv":"P-256","x":"AA","y":"AA"}]}`))
	require.ErrorContains(t, err, "unsupported key type")

	_, err = witbundle.Parse(td, []byte(`{"keys":[{"kty":"AKP","alg":"ML-DSA-65","kid":"KEY","pub":"AA","priv":"AA"}]}`))
	require.ErrorContains(t, err, "private material")
}

func TestSetDropsUnsupported(t *testing.T) {
	bundle := witbundle.New(td)
	key := newKey(t)
	bundle.SetWITAuthorities(map[string]crypto.PublicKey{"KEY": key, "CLASSICAL": nil})
	require.Len(t, bundle.WITAuthorities(), 1)
}

func TestGetWITBundleForTrustDomain(t *testing.T) {
	bundle := witbundle.New(td)
	got, err := bundle.GetWITBundleForTrustDomain(td)
	require.NoError(t, err)
	require.Same(t, bundle, got)
	_, err = bundle.GetWITBundleForTrustDomain(spiffeid.RequireTrustDomainFromString("other.test"))
	require.ErrorContains(t, err, "no WIT bundle")
}
