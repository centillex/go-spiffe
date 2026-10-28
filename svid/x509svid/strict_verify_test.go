package x509svid_test

import (
	"crypto"
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

func TestStrictPQVerify(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	id := spiffeid.RequireFromPath(td, "/workload")
	ca := test.NewPQCA(t, td)
	child := ca.ChildCA()
	svid := child.CreateX509SVID(id)
	got, chains, err := x509svid.Verify(svid.Certificates, ca.X509Bundle())
	require.NoError(t, err)
	require.Equal(t, id, got)
	require.Len(t, chains, 1)
	require.Len(t, chains[0], 3)
	for _, cert := range chains[0] {
		require.Equal(t, x509.MLDSA65, cert.SignatureAlgorithm)
	}
	_, _, err = x509svid.Verify(svid.Certificates, ca.X509Bundle(), x509svid.WithKeyUsage(x509.ExtKeyUsageAny))
	require.Error(t, err)
	_, _, err = x509svid.Verify(svid.Certificates, ca.X509Bundle(), x509svid.WithTime(svid.Certificates[0].NotAfter.Add(time.Second)))
	require.Error(t, err)
	_, _, err = x509svid.Verify([]*x509.Certificate{nil}, ca.X509Bundle())
	require.Error(t, err)
	_, err = x509svid.IDFromCert(nil)
	require.Error(t, err)
	// Mutable fields cannot substitute an identity that is not in the signed DER.
	modified := *svid.Certificates[0]
	modified.URIs = []*url.URL{spiffeid.RequireFromPath(td, "/other").URL()}
	got, _, err = x509svid.Verify([]*x509.Certificate{&modified, svid.Certificates[1]}, ca.X509Bundle())
	require.NoError(t, err)
	require.Equal(t, id, got)
}

func TestStrictPQRejectsCertificationPaths(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	key := func() crypto.Signer { k, err := mldsa.GenerateKey(mldsa.MLDSA65()); require.NoError(t, err); return k }
	for _, kind := range []string{"approved", "classical root", "classical intermediate", "classical leaf", "classical anchor signature", "MLDSA44 leaf"} {
		t.Run(kind, func(t *testing.T) {
			rootKey, interKey, leafKey := key(), key(), key()
			switch kind {
			case "classical root":
				rootKey = test.NewEC256Key(t)
			case "classical intermediate":
				interKey = test.NewEC256Key(t)
			case "classical leaf":
				leafKey = test.NewEC256Key(t)
			case "MLDSA44 leaf":
				k, err := mldsa.GenerateKey(mldsa.MLDSA44())
				require.NoError(t, err)
				leafKey = k
			}
			now := time.Now()
			rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
			var root *x509.Certificate
			if kind == "classical anchor signature" {
				parent, parentKey := test.CreateCACertificate(t, nil, nil)
				root = test.CreateCertificate(t, rootTemplate, parent, rootKey.Public(), parentKey)
			} else {
				root = test.CreateCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
			}
			interTemplate := *rootTemplate
			interTemplate.SerialNumber = big.NewInt(2)
			interTemplate.Subject = pkix.Name{CommonName: "intermediate"}
			intermediate := test.CreateCertificate(t, &interTemplate, root, interKey.Public(), rootKey)
			leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{spiffeid.RequireFromPath(td, "/workload").URL()}}
			leaf := test.CreateCertificate(t, leafTemplate, intermediate, leafKey.Public(), interKey)
			bundle := x509bundle.FromX509Authorities(td, []*x509.Certificate{root})
			_, _, err := x509svid.Verify([]*x509.Certificate{leaf, intermediate}, bundle)
			if kind == "approved" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestStrictPQVerifyUsageAndIdentity(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	for _, tc := range []struct {
		name    string
		opts    []test.SVIDOption
		usage   x509.ExtKeyUsage
		success bool
	}{
		{"server role", []test.SVIDOption{test.WithExtKeyUsage(x509.ExtKeyUsageServerAuth)}, x509.ExtKeyUsageServerAuth, true},
		{"wrong role", []test.SVIDOption{test.WithExtKeyUsage(x509.ExtKeyUsageClientAuth)}, x509.ExtKeyUsageServerAuth, false},
		{"no digital signature", []test.SVIDOption{test.WithKeyUsage(0)}, x509.ExtKeyUsageServerAuth, false},
		{"expired", []test.SVIDOption{test.WithLifetime(time.Now().Add(-time.Hour), time.Now().Add(-time.Minute))}, x509.ExtKeyUsageServerAuth, false},
		{"root identity", []test.SVIDOption{test.WithURIs(spiffeid.RequireFromPath(td, "").URL())}, x509.ExtKeyUsageServerAuth, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := append([]test.SVIDOption{test.WithURIs(spiffeid.RequireFromPath(td, "/workload").URL())}, tc.opts...)
			certs, _ := ca.CreateX509Certificate(options...)
			_, _, err := x509svid.Verify(certs, ca.X509Bundle(), x509svid.WithKeyUsage(tc.usage))
			if tc.success {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
