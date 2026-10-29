package spiffebundle_test

import (
	"crypto/x509"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

var (
	b1  = spiffebundle.New(td)
	td2 = spiffeid.RequireTrustDomainFromString("domain2.test")
)

func testCert(t *testing.T) *x509.Certificate {
	return test.NewCA(t, td).X509Authorities()[0]
}

func TestNewSet(t *testing.T) {
	s := spiffebundle.NewSet(b1)
	require.True(t, s.Has(td))

	s = spiffebundle.NewSet(spiffebundle.New(td), spiffebundle.New(td2))
	require.True(t, s.Has(td))
	require.True(t, s.Has(td2))
}

func TestAdd(t *testing.T) {
	s := spiffebundle.NewSet()
	require.False(t, s.Has(td))
	s.Add(b1)
	require.True(t, s.Has(td))
}

func TestRemove(t *testing.T) {
	s := spiffebundle.NewSet(b1)
	require.True(t, s.Has(td))
	s.Remove(td2)
	require.True(t, s.Has(td))
	s.Remove(td)
	require.False(t, s.Has(td))
}

func TestHas(t *testing.T) {
	s := spiffebundle.NewSet(spiffebundle.New(td))
	require.False(t, s.Has(td2))
	require.True(t, s.Has(td))
}

func TestSetGetBundleForTrustDomain(t *testing.T) {
	s := spiffebundle.NewSet(b1)
	_, err := s.GetBundleForTrustDomain(td2)
	require.EqualError(t, err, `spiffebundle: no SPIFFE bundle for trust domain "domain2.test"`)

	b, err := s.GetBundleForTrustDomain(td)
	require.NoError(t, err)
	require.Equal(t, b1, b)
}

func TestSetGetX509BundleForTrustDomain(t *testing.T) {
	xb1 := x509bundle.FromX509Authorities(td, []*x509.Certificate{testCert(t)})
	b := spiffebundle.FromX509Bundle(xb1)
	s := spiffebundle.NewSet(b)
	_, err := s.GetX509BundleForTrustDomain(td2)
	require.EqualError(t, err, `spiffebundle: no X.509 bundle for trust domain "domain2.test"`)

	xb2, err := s.GetX509BundleForTrustDomain(td)
	require.NoError(t, err)
	require.Equal(t, xb1, xb2)
}

func TestSetGetJWTBundleForTrustDomainIsUnsupported(t *testing.T) {
	s := spiffebundle.NewSet(b1)
	for _, trustDomain := range []spiffeid.TrustDomain{td, td2} {
		b, err := s.GetJWTBundleForTrustDomain(trustDomain)
		require.ErrorIs(t, err, pqprofile.ErrUnsupported)
		require.Nil(t, b)
	}
}

func TestSetGetWITBundleForTrustDomainIsUnsupported(t *testing.T) {
	s := spiffebundle.NewSet(b1)
	for _, trustDomain := range []spiffeid.TrustDomain{td, td2} {
		b, err := s.GetWITBundleForTrustDomain(trustDomain)
		require.ErrorIs(t, err, pqprofile.ErrUnsupported)
		require.Nil(t, b)
	}
}
