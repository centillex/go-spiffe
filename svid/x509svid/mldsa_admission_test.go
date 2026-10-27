package x509svid

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// These locally issued fixtures test loading, not deployment issuance or trust.
func mldsaTestSVID(t testing.TB, params mldsa.Parameters) *SVID {
	t.Helper()
	key, err := mldsa.GenerateKey(params)
	require.NoError(t, err)
	uri, err := url.Parse("spiffe://example.org/workload")
	require.NoError(t, err)
	now := time.Now()
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, key.Public(), key)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	leafKey, err := mldsa.GenerateKey(params)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(2), URIs: []*url.URL{uri}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, root, leafKey.Public(), key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	id, err := IDFromCert(leaf)
	require.NoError(t, err)
	return &SVID{ID: id, Certificates: []*x509.Certificate{leaf, root}, PrivateKey: leafKey}
}

func TestMLDSAChainAndSignerRoundTrip(t *testing.T) {
	original := mldsaTestSVID(t, mldsa.MLDSA65())
	certDER, keyDER, err := original.MarshalRaw()
	require.NoError(t, err)
	loaded, err := ParseRaw(certDER, keyDER)
	require.NoError(t, err)
	require.Equal(t, original.ID, loaded.ID)
	require.Len(t, loaded.Certificates, 2)
	for i, cert := range original.Certificates {
		require.Equal(t, cert.Raw, loaded.Certificates[i].Raw)
	}
	certPEM, keyPEM, err := loaded.Marshal()
	require.NoError(t, err)
	// Public Load supports combined certificate/key files.
	path := filepath.Join(t.TempDir(), "svid.pem")
	require.NoError(t, os.WriteFile(path, append(certPEM, keyPEM...), 0600))
	loaded, err = Load(path, path)
	require.NoError(t, err)
	require.Equal(t, original.ID, loaded.ID)
	message := []byte("ML-DSA loader signer correspondence test")
	signature, err := loaded.PrivateKey.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)
	require.NoError(t, mldsa.Verify(loaded.Certificates[0].PublicKey.(*mldsa.PublicKey), message, signature, nil))
}

func TestMLDSALoaderRejectsUnapprovedParameters(t *testing.T) {
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			svid := mldsaTestSVID(t, params)
			keyDER, err := x509.MarshalPKCS8PrivateKey(svid.PrivateKey)
			require.NoError(t, err)
			// Bypass SVID.Marshal to test loader admission with well-formed keys.
			certDER := svid.Certificates[0].Raw
			certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
			_, err = ParseRaw(certDER, keyDER)
			require.ErrorContains(t, err, "qspiffe-pq-v1: unsupported ML-DSA")
			_, err = Parse(certPEM, keyPEM)
			require.ErrorContains(t, err, "qspiffe-pq-v1: unsupported ML-DSA")
			path := filepath.Join(t.TempDir(), "svid.pem")
			require.NoError(t, os.WriteFile(path, append(certPEM, keyPEM...), 0600))
			_, err = Load(path, path)
			require.ErrorContains(t, err, "qspiffe-pq-v1: unsupported ML-DSA")
			_, _, err = svid.Marshal()
			require.Error(t, err)
			_, _, err = svid.MarshalRaw()
			require.Error(t, err)
			// Matching keys still work at the algorithm-capability layer.
			matches, err := keyMatches(svid.PrivateKey, svid.Certificates[0].PublicKey)
			require.NoError(t, err)
			require.True(t, matches)
			// Also reject unapproved non-leaf keys at the loader boundary.
			approved := mldsaTestSVID(t, mldsa.MLDSA65())
			_, err = newSVID([]*x509.Certificate{approved.Certificates[0], svid.Certificates[1]}, approved.PrivateKey)
			require.ErrorContains(t, err, "qspiffe-pq-v1: unsupported ML-DSA")
		})
	}
}

func TestMLDSARejectsAmbiguousAndMalformedKeys(t *testing.T) {
	svid := mldsaTestSVID(t, mldsa.MLDSA65())
	certDER, keyDER, err := svid.MarshalRaw()
	require.NoError(t, err)
	certPEM, keyPEM, err := svid.Marshal()
	require.NoError(t, err)
	_, err = Parse(certPEM, append(append([]byte{}, keyPEM...), keyPEM...))
	require.ErrorContains(t, err, "multiple private keys")
	for _, bad := range [][]byte{nil, {}, {1, 2, 3}, keyDER[:len(keyDER)-1], append(append([]byte{}, keyDER...), 0), append(append([]byte{}, keyDER...), keyDER...)} {
		_, err := ParseRaw(certDER, bad)
		require.Error(t, err)
		_, err = Parse(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: bad}))
		require.Error(t, err)
	}
	// PKCS#8 may contain non-signing keys; parsing one must not bypass signer requirements.
	unsupported, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	unsupportedDER, err := x509.MarshalPKCS8PrivateKey(unsupported)
	require.NoError(t, err)
	_, err = ParseRaw(certDER, unsupportedDER)
	require.ErrorContains(t, err, "unsupported private key type")

	// Native interchange accepts the seed form only, without algorithm parameters.
	var envelope struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	_, err = asn1.Unmarshal(keyDER, &envelope)
	require.NoError(t, err)
	original := envelope
	for _, bad := range [][]byte{
		{0x80, 0}, // empty seed
		append([]byte{0x80, 31}, make([]byte, 31)...), // short seed
		append([]byte{0x04, 32}, make([]byte, 32)...), // OCTET STRING, not seed choice
	} {
		envelope.PrivateKey = bad
		badDER, err := asn1.Marshal(envelope)
		require.NoError(t, err)
		_, err = ParseRaw(certDER, badDER)
		require.Error(t, err)
	}
	envelope = original
	envelope.Algorithm.Parameters = asn1.NullRawValue
	badDER, err := asn1.Marshal(envelope)
	require.NoError(t, err)
	_, err = ParseRaw(certDER, badDER)
	require.Error(t, err)

	// Corrupt each certificate/key independently; neither may be silently ignored.
	_, err = Parse(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}), keyPEM)
	require.Error(t, err)
}

func TestMarshalRejectsInvalidObjects(t *testing.T) {
	good := mldsaTestSVID(t, mldsa.MLDSA65())
	bad := []*SVID{nil, {}, {Certificates: []*x509.Certificate{nil}, PrivateKey: good.PrivateKey}, {Certificates: []*x509.Certificate{{}}, PrivateKey: good.PrivateKey}}
	for _, key := range []crypto.Signer{nil, (*mldsa.PrivateKey)(nil), &mldsa.PrivateKey{}, (*rsa.PrivateKey)(nil), (*ecdsa.PrivateKey)(nil), ed25519.PrivateKey(nil), ed25519.PrivateKey{1}} {
		bad = append(bad, &SVID{ID: good.ID, Certificates: good.Certificates, PrivateKey: key})
	}
	wrong, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	bad = append(bad, &SVID{ID: good.ID, Certificates: good.Certificates, PrivateKey: wrong})
	for _, svid := range bad {
		cert, key, err := svid.Marshal()
		require.Error(t, err)
		require.Nil(t, cert)
		require.Nil(t, key)
		cert, key, err = svid.MarshalRaw()
		require.Error(t, err)
		require.Nil(t, cert)
		require.Nil(t, key)
	}
	_, err = validatePrivateKey(good.PrivateKey, nil)
	require.Error(t, err)
}

func FuzzMLDSAParseRaw(f *testing.F) {
	svid := mldsaTestSVID(f, mldsa.MLDSA65())
	cert, key, err := svid.MarshalRaw()
	require.NoError(f, err)
	f.Add(cert, key)
	f.Add([]byte{1, 2, 3}, []byte{4, 5, 6})
	f.Fuzz(func(t *testing.T, cert, key []byte) {
		svid, err := ParseRaw(cert, key)
		if err != nil {
			return
		}
		cert2, key2, err := svid.MarshalRaw()
		require.NoError(t, err)
		again, err := ParseRaw(cert2, key2)
		require.NoError(t, err)
		require.Equal(t, svid.ID, again.ID)
	})
}
