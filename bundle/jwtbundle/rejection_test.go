package jwtbundle_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

var (
	td      = spiffeid.RequireTrustDomainFromString("domain.test")
	otherTD = spiffeid.RequireTrustDomainFromString("other.test")
	jwksDoc = []byte(`{"keys":[{"kty":"EC","kid":"KEY","crv":"P-256","x":"abc","y":"def"}]}`)
)

// TestUnsupportedOperations pins the strict-profile boundary: no JWT trust can
// be admitted, parsed, served, or marshaled, and every failure is the shared
// sentinel rather than a classical fallback.
func TestUnsupportedOperations(t *testing.T) {
	bundle := jwtbundle.New(td)

	_, err := jwtbundle.Load(td, filepath.Join(t.TempDir(), "missing.json"))
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	_, err = jwtbundle.Read(td, bytes.NewReader(jwksDoc))
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	_, err = jwtbundle.Parse(td, jwksDoc)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	_, err = bundle.Marshal()
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	_, err = bundle.GetJWTBundleForTrustDomain(td)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
}

func TestAuthoritiesAreNeverAdmitted(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	authorities := map[string]crypto.PublicKey{"KEY": &key.PublicKey}

	bundle := jwtbundle.FromJWTAuthorities(td, authorities)
	require.True(t, bundle.Empty())
	require.Empty(t, bundle.JWTAuthorities())
	require.False(t, bundle.HasJWTAuthority("KEY"))
	_, ok := bundle.FindJWTAuthority("KEY")
	require.False(t, ok)

	require.ErrorIs(t, bundle.AddJWTAuthority("KEY", &key.PublicKey), pqprofile.ErrUnsupported)
	bundle.SetJWTAuthorities(authorities)
	bundle.RemoveJWTAuthority("KEY")
	require.True(t, bundle.Empty())
	require.Empty(t, bundle.JWTAuthorities())
}

func TestBundleIdentityAndEquality(t *testing.T) {
	bundle := jwtbundle.FromJWTAuthorities(td, nil)
	require.Equal(t, td, bundle.TrustDomain())
	require.True(t, bundle.Equal(jwtbundle.New(td)))
	require.False(t, bundle.Equal(jwtbundle.New(otherTD)))
	require.False(t, bundle.Equal(nil))
	require.True(t, bundle.Clone().Equal(bundle))
	var nilBundle *jwtbundle.Bundle
	require.Nil(t, nilBundle.Clone())
	require.True(t, nilBundle.Equal(nil))
}

func TestLoadRejectsBeforeReading(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	require.NoError(t, os.WriteFile(path, jwksDoc, 0600))
	_, err := jwtbundle.Load(td, path)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
}
