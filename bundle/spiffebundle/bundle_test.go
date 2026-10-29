package spiffebundle_test

import (
	"bytes"
	"crypto"
	"os"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

var td = spiffeid.RequireTrustDomainFromString("domain.test")

const (
	x509OnlyPath     = "testdata/spiffebundle_x509_only.json"
	x509MetadataPath = "testdata/spiffebundle_x509_metadata.json"
	multiX509Path    = "testdata/spiffebundle_multiple_x509_only.json"
	noKeysPath       = "testdata/spiffebundle_no_keys.json"
	jwtEntryPath     = "testdata/spiffebundle_jwt_entry.json"
	witEntryPath     = "testdata/spiffebundle_wit_entry.json"
)

func TestNew(t *testing.T) {
	b := spiffebundle.New(td)
	require.NotNil(t, b)
	require.Empty(t, b.JWTAuthorities())
	require.Empty(t, b.WITAuthorities())
	require.Equal(t, td, b.TrustDomain())
}

func TestLoadReadParseX509(t *testing.T) {
	bundle, err := spiffebundle.Load(td, x509OnlyPath)
	require.NoError(t, err)
	require.Len(t, bundle.X509Authorities(), 1)
	require.Empty(t, bundle.JWTAuthorities())
	require.Empty(t, bundle.WITAuthorities())

	data, err := os.ReadFile(x509OnlyPath)
	require.NoError(t, err)

	bundle, err = spiffebundle.Read(td, bytes.NewReader(data))
	require.NoError(t, err)
	require.Len(t, bundle.X509Authorities(), 1)

	bundle, err = spiffebundle.Parse(td, data)
	require.NoError(t, err)
	require.Len(t, bundle.X509Authorities(), 1)

	// The X.509-only reader rejects classical authorities by design.
	_, err = spiffebundle.ParseX509Only(td, data)
	require.ErrorContains(t, err, "classical X.509 authority")
}

func TestLoadMetadata(t *testing.T) {
	bundle, err := spiffebundle.Load(td, x509MetadataPath)
	require.NoError(t, err)
	hint, ok := bundle.RefreshHint()
	require.True(t, ok)
	require.Equal(t, 60*time.Second, hint)
	sequence, ok := bundle.SequenceNumber()
	require.True(t, ok)
	require.Equal(t, uint64(1), sequence)
}

func TestParseFailures(t *testing.T) {
	_, err := spiffebundle.Load(td, "testdata/does-not-exist.json")
	require.Error(t, err)

	_, err = spiffebundle.Load(td, noKeysPath)
	require.Error(t, err)

	// Token entries are rejected by the general reader instead of being
	// admitted as token trust.
	_, err = spiffebundle.Load(td, jwtEntryPath)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	_, err = spiffebundle.Load(td, witEntryPath)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	// The X.509-only reader discards token entries and never admits them.
	data, err := os.ReadFile(jwtEntryPath)
	require.NoError(t, err)
	bundle, err := spiffebundle.ParseX509Only(td, data)
	require.NoError(t, err)
	require.True(t, bundle.Empty())
	require.Empty(t, bundle.JWTAuthorities())
	require.Empty(t, bundle.WITAuthorities())
}

func TestMultipleX509CertificatesUseFirst(t *testing.T) {
	bundle, err := spiffebundle.Load(td, multiX509Path)
	require.NoError(t, err)
	require.Len(t, bundle.X509Authorities(), 1)
}

func TestFromX509(t *testing.T) {
	ca := test.NewCA(t, td)
	fromBundle := spiffebundle.FromX509Bundle(ca.X509Bundle())
	require.Equal(t, td, fromBundle.TrustDomain())
	require.Equal(t, ca.X509Authorities(), fromBundle.X509Authorities())

	fromAuthorities := spiffebundle.FromX509Authorities(td, ca.X509Authorities())
	require.True(t, fromBundle.Equal(fromAuthorities))
}

func TestX509AuthoritiesCRUD(t *testing.T) {
	bundle := spiffebundle.New(td)
	require.Empty(t, bundle.X509Authorities())

	ca := test.NewCA(t, td)
	bundle.AddX509Authority(ca.X509Authorities()[0])
	require.Len(t, bundle.X509Authorities(), 1)

	bundle.SetX509Authorities(nil)
	require.Empty(t, bundle.X509Authorities())
}

func TestX509Bundle(t *testing.T) {
	ca := test.NewCA(t, td)
	bundle := spiffebundle.FromX509Bundle(ca.X509Bundle())
	require.True(t, bundle.X509Bundle().Equal(ca.X509Bundle()))

	got, err := bundle.GetX509BundleForTrustDomain(td)
	require.NoError(t, err)
	require.True(t, got.Equal(ca.X509Bundle()))

	other := spiffeid.RequireTrustDomainFromString("other.test")
	_, err = bundle.GetX509BundleForTrustDomain(other)
	require.Error(t, err)
}

func TestGetBundleForTrustDomain(t *testing.T) {
	bundle := spiffebundle.New(td)
	got, err := bundle.GetBundleForTrustDomain(td)
	require.NoError(t, err)
	require.Same(t, bundle, got)

	_, err = bundle.GetBundleForTrustDomain(spiffeid.RequireTrustDomainFromString("other.test"))
	require.Error(t, err)
}

func TestMarshalRoundTrip(t *testing.T) {
	ca := test.NewPQCA(t, td)
	bundle := spiffebundle.FromX509Bundle(ca.X509Bundle())
	bundle.SetSequenceNumber(3)
	bundle.SetRefreshHint(time.Minute)

	data, err := bundle.Marshal()
	require.NoError(t, err)
	require.Contains(t, string(data), `"use":"x509-svid"`)
	require.NotContains(t, string(data), `"jwt-svid"`)
	require.NotContains(t, string(data), `"wit-svid"`)

	parsed, err := spiffebundle.ParseX509Only(td, data)
	require.NoError(t, err)
	require.True(t, bundle.Equal(parsed))
}

func TestEqualAndClone(t *testing.T) {
	ca := test.NewCA(t, td)
	bundle := spiffebundle.FromX509Bundle(ca.X509Bundle())

	require.True(t, bundle.Equal(bundle.Clone()))
	require.False(t, bundle.Equal(spiffebundle.New(td)))
	require.False(t, bundle.Equal(nil))

	clone := bundle.Clone()
	clone.AddX509Authority(test.NewCA(t, td).X509Authorities()[0])
	require.Len(t, bundle.X509Authorities(), 1)
}

// TestTokenOperationsUnsupported pins the strict-profile boundary for token
// trust admission and lookup on the combined SPIFFE bundle.
func TestTokenOperationsUnsupported(t *testing.T) {
	key := test.NewEC256Key(t)
	authorities := map[string]crypto.PublicKey{"KEY": key}

	bundle := spiffebundle.FromJWTAuthorities(td, authorities)
	require.Empty(t, bundle.JWTAuthorities())
	require.False(t, bundle.HasJWTAuthority("KEY"))
	_, ok := bundle.FindJWTAuthority("KEY")
	require.False(t, ok)

	bundle = spiffebundle.FromWITAuthorities(td, authorities)
	require.Empty(t, bundle.WITAuthorities())
	require.False(t, bundle.HasWITAuthority("KEY"))

	require.ErrorIs(t, bundle.AddJWTAuthority("KEY", key), pqprofile.ErrUnsupported)
	require.ErrorIs(t, bundle.AddWITAuthority("KEY", key), pqprofile.ErrUnsupported)
	bundle.SetJWTAuthorities(authorities)
	bundle.SetWITAuthorities(authorities)
	bundle.RemoveJWTAuthority("KEY")
	bundle.RemoveWITAuthority("KEY")
	require.Empty(t, bundle.JWTAuthorities())
	require.Empty(t, bundle.WITAuthorities())

	require.True(t, bundle.JWTBundle().Empty())
	require.True(t, bundle.WITBundle().Empty())

	_, err := bundle.GetJWTBundleForTrustDomain(td)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
	_, err = bundle.GetWITBundleForTrustDomain(td)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	// Constructors from token bundles remain empty regardless of input.
	require.True(t, spiffebundle.FromJWTBundle(jwtbundle.New(td)).Empty())
	require.True(t, spiffebundle.FromWITBundle(witbundle.New(td)).Empty())
}
