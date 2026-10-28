package pqjwk_test

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/internal/pqjwk"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

func fixture(t testing.TB) (*x509.Certificate, []byte) {
	t.Helper()
	cert := test.NewPQCA(t, spiffeid.RequireTrustDomainFromString("pq.example")).X509Authorities()[0]
	encoded, err := pqjwk.MarshalX509Authority(cert)
	require.NoError(t, err)
	return cert, encoded
}

func TestCertificateEntryRoundTrip(t *testing.T) {
	cert, encoded := fixture(t)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &fields))
	require.Len(t, fields, 5)
	require.JSONEq(t, `"AKP"`, string(fields["kty"]))
	require.JSONEq(t, `"ML-DSA-65"`, string(fields["alg"]))
	require.JSONEq(t, `"x509-svid"`, string(fields["use"]))
	var pub string
	require.NoError(t, json.Unmarshal(fields["pub"], &pub))
	raw, err := base64.RawURLEncoding.DecodeString(pub)
	require.NoError(t, err)
	require.Len(t, raw, 1952)
	parsed, err := pqjwk.ParseX509Authority(encoded)
	require.NoError(t, err)
	require.Equal(t, cert.Raw, parsed.Raw)
	reencoded, err := pqjwk.MarshalX509Authority(parsed)
	require.NoError(t, err)
	require.Equal(t, encoded, reencoded)
	// Metadata and alias mutation cannot replace the signed DER authority.
	cert.PublicKey = nil
	cert.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
	cert.IsCA = false
	reencoded, err = pqjwk.MarshalX509Authority(cert)
	require.NoError(t, err)
	require.Equal(t, encoded, reencoded)
	cert.Raw[0] = 0
	require.NotEqual(t, cert.Raw, parsed.Raw)
}

func TestCertificateEntryMetadata(t *testing.T) {
	cert, encoded := fixture(t)
	tests := map[string]func(map[string]any){
		"wrong type":        func(m map[string]any) { m["kty"] = "OKP" },
		"wrong use":         func(m map[string]any) { m["use"] = "jwt-svid" },
		"MLDSA44":           func(m map[string]any) { m["alg"] = "ML-DSA-44" },
		"MLDSA87":           func(m map[string]any) { m["alg"] = "ML-DSA-87" },
		"missing algorithm": func(m map[string]any) { delete(m, "alg") },
		"null algorithm":    func(m map[string]any) { m["alg"] = nil },
		"wrong case":        func(m map[string]any) { m["KTY"] = m["kty"]; delete(m, "kty") },
		"missing pub":       func(m map[string]any) { delete(m, "pub") },
		"short pub":         func(m map[string]any) { m["pub"] = "AAAA" },
		"padded pub":        func(m map[string]any) { m["pub"] = m["pub"].(string) + "=" },
		"pub newline":       func(m map[string]any) { m["pub"] = m["pub"].(string) + "\n" },
		"key substitution": func(m map[string]any) {
			p := cert.PublicKey.(*mldsa.PublicKey).Bytes()
			p[0] ^= 1
			m["pub"] = base64.RawURLEncoding.EncodeToString(p)
		},
		"private material":        func(m map[string]any) { m["priv"] = "not a private key" },
		"null private material":   func(m map[string]any) { m["priv"] = nil },
		"kid":                     func(m map[string]any) { m["kid"] = "" },
		"competing key":           func(m map[string]any) { m["crv"] = "ML-DSA-65" },
		"private RSA field":       func(m map[string]any) { m["d"] = "" },
		"no certificate":          func(m map[string]any) { delete(m, "x5c") },
		"empty certificates":      func(m map[string]any) { m["x5c"] = []string{} },
		"bad DER":                 func(m map[string]any) { m["x5c"] = []string{"AAAA"} },
		"certificate newline":     func(m map[string]any) { m["x5c"] = []string{base64.StdEncoding.EncodeToString(cert.Raw) + "\n"} },
		"SHA1 thumbprint":         func(m map[string]any) { m["x5t"] = "" },
		"wrong SHA256 thumbprint": func(m map[string]any) { m["x5t#S256"] = "AAAA" },
		"sign operation":          func(m map[string]any) { m["key_ops"] = []string{"sign"} },
		"duplicate operation":     func(m map[string]any) { m["key_ops"] = []string{"verify", "verify"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			require.NoError(t, json.Unmarshal(encoded, &m))
			mutate(m)
			input, err := json.Marshal(m)
			require.NoError(t, err)
			got, err := pqjwk.ParseX509Authority(input)
			require.Error(t, err)
			require.Nil(t, got)
		})
	}
	var m map[string]any
	require.NoError(t, json.Unmarshal(encoded, &m))
	hash := sha256.Sum256(cert.Raw)
	m["x5t#S256"] = base64.RawURLEncoding.EncodeToString(hash[:])
	m["key_ops"] = []string{"verify"}
	m["extension"] = map[string]any{"untrusted": true}
	// Additional certificates are discarded, never parsed or admitted as roots.
	m["x5c"] = []string{base64.StdEncoding.EncodeToString(cert.Raw), "not a certificate"}
	input, err := json.Marshal(m)
	require.NoError(t, err)
	parsed, err := pqjwk.ParseX509Authority(input)
	require.NoError(t, err)
	require.Equal(t, cert.Raw, parsed.Raw)
}

func TestCertificateEntryAmbiguousJSON(t *testing.T) {
	_, encoded := fixture(t)
	for _, input := range [][]byte{
		nil, []byte("null"), []byte("[]"), []byte(`{"kty":"AKP"`),
		append(bytes.Clone(encoded), []byte(" {}")...),
		append([]byte(`{"kty":"AKP",`), encoded[1:]...),
		append([]byte(`{"\u006bty":"AKP",`), encoded[1:]...),
		[]byte{'{', '"', 0xff, '"', ':', '1', '}'},
	} {
		got, err := pqjwk.ParseX509Authority(input)
		require.Error(t, err)
		require.Nil(t, got)
	}
}

func TestCertificateEntryAuthorityAdmission(t *testing.T) {
	classical := test.NewCA(t, spiffeid.RequireTrustDomainFromString("pq.example")).X509Authorities()[0]
	for _, cert := range []*x509.Certificate{nil, {}, classical} {
		_, err := pqjwk.MarshalX509Authority(cert)
		require.Error(t, err)
	}
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		key, err := mldsa.GenerateKey(params)
		require.NoError(t, err)
		for _, isCA := range []bool{false, true} {
			template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic authority"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: isCA, KeyUsage: x509.KeyUsageCertSign}
			cert := test.CreateCertificate(t, template, template, key.Public(), key)
			_, err := pqjwk.MarshalX509Authority(cert)
			if params == mldsa.MLDSA65() && isCA {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		}
	}
}

func FuzzParseCertificateEntry(f *testing.F) {
	_, encoded := fixture(f)
	f.Add(encoded)
	f.Add([]byte(`{"kty":"AKP","kty":"AKP"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		cert, err := pqjwk.ParseX509Authority(data)
		if err != nil {
			require.Nil(t, cert)
			return
		}
		encoded, err := pqjwk.MarshalX509Authority(cert)
		require.NoError(t, err)
		roundTrip, err := pqjwk.ParseX509Authority(encoded)
		require.NoError(t, err)
		require.Equal(t, cert.Raw, roundTrip.Raw)
	})
}
