package test

import (
	"crypto"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

// NewPQCA creates local synthetic ML-DSA-65 credentials, not deployment evidence.
func NewPQCA(tb testing.TB, td spiffeid.TrustDomain) *CA {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(tb, err)
	now := time.Now()
	serial := NewSerial(tb)
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: fmt.Sprintf("PQ test CA %x", serial)}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	cert := CreateCertificate(tb, template, template, key.Public(), key)
	return &CA{tb: tb, td: td, cert: cert, key: key, jwtKey: NewEC256Key(tb), jwtKid: NewKeyID(tb)}
}

func CreatePQWebCredentials(tb testing.TB) (*x509.CertPool, *tls.Certificate) {
	ca := NewPQCA(tb, spiffeid.RequireTrustDomainFromString("web.example"))
	certs, key := ca.CreateX509Certificate(WithIPAddresses(localhostIPs...))
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	cert := &tls.Certificate{PrivateKey: key}
	for _, c := range certs {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	return roots, cert
}

func newX509Key(tb testing.TB, parent crypto.Signer) crypto.Signer {
	if key, ok := parent.(*mldsa.PrivateKey); ok {
		generated, err := mldsa.GenerateKey(key.PublicKey().Parameters())
		require.NoError(tb, err)
		return generated
	}
	return NewEC256Key(tb)
}
