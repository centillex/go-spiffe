package witbundle_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

var (
	td      = spiffeid.RequireTrustDomainFromString("domain.test")
	td2     = spiffeid.RequireTrustDomainFromString("other.org")
	jwksDoc = []byte(`{"keys":[{"kty":"EC","kid":"KEY","crv":"P-256","x":"abc","y":"def","use":"wit-svid"}]}`)
)

func TestUnsupportedOperations(t *testing.T) {
	bundle := witbundle.New(td)

	_, err := witbundle.Load(td, filepath.Join(t.TempDir(), "missing.json"))
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	_, err = witbundle.Read(td, bytes.NewReader(jwksDoc))
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	_, err = witbundle.Parse(td, jwksDoc)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	_, err = bundle.Marshal()
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	_, err = bundle.GetWITBundleForTrustDomain(td)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
}

func TestAuthoritiesAreNeverAdmitted(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	authorities := map[string]crypto.PublicKey{"KEY": &key.PublicKey}

	bundle := witbundle.FromWITAuthorities(td, authorities)
	require.True(t, bundle.Empty())
	require.Empty(t, bundle.WITAuthorities())
	require.False(t, bundle.HasWITAuthority("KEY"))
	_, ok := bundle.FindWITAuthority("KEY")
	require.False(t, ok)

	require.ErrorIs(t, bundle.AddWITAuthority("KEY", &key.PublicKey), pqprofile.ErrUnsupported)
	bundle.SetWITAuthorities(authorities)
	bundle.RemoveWITAuthority("KEY")
	require.True(t, bundle.Empty())
	require.Empty(t, bundle.WITAuthorities())
}

func TestBundleIdentityAndEquality(t *testing.T) {
	bundle := witbundle.FromWITAuthorities(td, nil)
	require.Equal(t, td, bundle.TrustDomain())
	require.True(t, bundle.Equal(witbundle.New(td)))
	require.False(t, bundle.Equal(witbundle.New(td2)))
	require.False(t, bundle.Equal(nil))
	require.True(t, bundle.Clone().Equal(bundle))
	var nilBundle *witbundle.Bundle
	require.Nil(t, nilBundle.Clone())
	require.True(t, nilBundle.Equal(nil))
}

func TestLoadRejectsBeforeReading(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	require.NoError(t, os.WriteFile(path, jwksDoc, 0600))
	_, err := witbundle.Load(td, path)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
}
