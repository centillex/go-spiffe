package x509svid_test

import (
	"crypto/mldsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"
)

func TestStrictPQAlternativePaths(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	newKey := func() *mldsa.PrivateKey { k, e := mldsa.GenerateKey(mldsa.MLDSA65()); require.NoError(t, e); return k }
	rootKey, interKey, leafKey := newKey(), newKey(), newKey()
	now := time.Now()
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PQ root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root := test.CreateCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	classicalRoot, classicalKey := test.CreateCACertificate(t, nil, nil)
	interTemplate := *rootTemplate
	interTemplate.Subject = pkix.Name{CommonName: "Cross-signed intermediate"}
	interTemplate.SerialNumber = big.NewInt(2)
	approved := test.CreateCertificate(t, &interTemplate, root, interKey.Public(), rootKey)
	mixed := test.CreateCertificate(t, &interTemplate, classicalRoot, interKey.Public(), classicalKey)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{spiffeid.RequireFromPath(td, "/workload").URL()}}
	leaf := test.CreateCertificate(t, leafTemplate, approved, leafKey.Public(), interKey)
	roots := x509bundle.FromX509Authorities(td, []*x509.Certificate{classicalRoot, root})
	// Establish that native X.509 accepts both candidate paths; policy must
	// filter the mixed one rather than succeeding due to absent alternatives.
	nativeRoots, nativeIntermediates := x509.NewCertPool(), x509.NewCertPool()
	nativeRoots.AddCert(classicalRoot)
	nativeRoots.AddCert(root)
	nativeIntermediates.AddCert(mixed)
	nativeIntermediates.AddCert(approved)
	nativeChains, err := leaf.Verify(x509.VerifyOptions{Roots: nativeRoots, Intermediates: nativeIntermediates})
	require.NoError(t, err)
	require.Len(t, nativeChains, 2)
	for _, intermediates := range [][]*x509.Certificate{{mixed, approved}, {approved, mixed}} {
		presented := append([]*x509.Certificate{leaf}, intermediates...)
		_, chains, err := x509svid.Verify(presented, roots)
		require.NoError(t, err)
		require.NotEmpty(t, chains)
		for _, chain := range chains {
			require.Len(t, chain, 3)
			require.Equal(t, approved.Raw, chain[1].Raw)
			require.Equal(t, root.Raw, chain[2].Raw)
		}
	}
	_, _, err = x509svid.Verify([]*x509.Certificate{leaf, mixed}, x509bundle.FromX509Authorities(td, []*x509.Certificate{classicalRoot}))
	require.ErrorContains(t, err, "no approved certification path")
	corrupt := append([]byte(nil), leaf.Raw...)
	corrupt[len(corrupt)-1] ^= 1
	bad, err := x509.ParseCertificate(corrupt)
	require.NoError(t, err)
	_, _, err = x509svid.Verify([]*x509.Certificate{bad, approved}, roots)
	require.Error(t, err, "algorithm admission must not replace signature verification")
}
