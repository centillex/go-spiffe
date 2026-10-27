package x509svid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This tests loader capability, not strict-profile authentication admission.
func TestMLDSALoading(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	uri, err := url.Parse("spiffe://example.org/workload")
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), URIs: []*url.URL{uri}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	svid, err := ParseRaw(der, pkcs8)
	require.NoError(t, err)
	require.Equal(t, uri.String(), svid.ID.String())
	require.True(t, key.Equal(svid.PrivateKey))
	certPEM, keyPEM, err := svid.Marshal()
	require.NoError(t, err)
	parsed, err := Parse(certPEM, keyPEM)
	require.NoError(t, err)
	require.Equal(t, svid.ID, parsed.ID)
	require.True(t, key.Equal(parsed.PrivateKey))
	certRaw, keyRaw, err := parsed.MarshalRaw()
	require.NoError(t, err)
	require.Equal(t, der, certRaw)
	require.Equal(t, pkcs8, keyRaw)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "svid.pem"), filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, certPEM, 0600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0600))
	loaded, err := Load(certFile, keyFile)
	require.NoError(t, err)
	require.True(t, key.Equal(loaded.PrivateKey))
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		wrong, err := mldsa.GenerateKey(params)
		require.NoError(t, err)
		wrongDER, err := x509.MarshalPKCS8PrivateKey(wrong)
		require.NoError(t, err)
		_, err = ParseRaw(der, wrongDER)
		require.Error(t, err)
		_, err = Parse(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: wrongDER}))
		require.Error(t, err)
	}
	for _, bad := range [][]byte{nil, {}, {1, 2, 3}, pkcs8[:len(pkcs8)/2]} {
		_, err := ParseRaw(der, bad)
		require.Error(t, err)
	}
	_, err = ParseRaw([]byte{1, 2, 3}, pkcs8)
	require.Error(t, err)
}

func TestKeyMatchingRejectsNilAndMalformed(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	for _, bad := range []crypto.PrivateKey{nil, (*mldsa.PrivateKey)(nil), (*rsa.PrivateKey)(nil), (*ecdsa.PrivateKey)(nil), ed25519.PrivateKey(nil), ed25519.PrivateKey{1}, "unsupported"} {
		matched, err := keyMatches(bad, key.Public())
		require.Error(t, err)
		require.False(t, matched)
	}
	matched, err := keyMatches(key, (*mldsa.PublicKey)(nil))
	require.NoError(t, err)
	require.False(t, matched)
	_, err = newSVID([]*x509.Certificate{nil}, key)
	require.Error(t, err)
}
