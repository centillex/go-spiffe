package spiffebundle_test

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

func TestPQBundlePublicRoundTrip(t *testing.T) {
	ca := test.NewPQCA(t, td)
	original := spiffebundle.FromX509Bundle(ca.X509Bundle())
	original.SetSequenceNumber(math.MaxUint64)
	original.SetRefreshHint(3 * time.Second)
	data, err := original.Marshal()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "bundle.json")
	require.NoError(t, os.WriteFile(path, data, 0600))
	for name, read := range map[string]func() (*spiffebundle.Bundle, error){
		"Parse":        func() (*spiffebundle.Bundle, error) { return spiffebundle.Parse(td, data) },
		"Read":         func() (*spiffebundle.Bundle, error) { return spiffebundle.Read(td, bytes.NewReader(data)) },
		"Load":         func() (*spiffebundle.Bundle, error) { return spiffebundle.Load(td, path) },
		"X509Only":     func() (*spiffebundle.Bundle, error) { return spiffebundle.ParseX509Only(td, data) },
		"ReadX509Only": func() (*spiffebundle.Bundle, error) { return spiffebundle.ReadX509Only(td, bytes.NewReader(data)) },
	} {
		t.Run(name, func(t *testing.T) {
			parsed, err := read()
			require.NoError(t, err)
			require.True(t, original.Equal(parsed))
			require.True(t, parsed.Equal(parsed.Clone()))
			require.Equal(t, td, parsed.TrustDomain())
			require.Equal(t, ca.X509Authorities()[0].Raw, parsed.X509Authorities()[0].Raw)
			_, err = parsed.GetX509BundleForTrustDomain(td2)
			require.Error(t, err)
			require.Empty(t, parsed.JWTAuthorities())
			require.Empty(t, parsed.WITAuthorities())
		})
	}
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &doc))
	doc["trust_domain"] = json.RawMessage(`"attacker.example"`)
	data, err = json.Marshal(doc)
	require.NoError(t, err)
	parsed, err := spiffebundle.ParseX509Only(td, data)
	require.NoError(t, err)
	require.Equal(t, td, parsed.TrustDomain())
}

func TestPQBundleOnlyReaderNeverAdmitsTokens(t *testing.T) {
	original := spiffebundle.FromX509Bundle(test.NewPQCA(t, td).X509Bundle())
	data, err := original.Marshal()
	require.NoError(t, err)
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(data, &doc))
	doc.Keys = append(doc.Keys, json.RawMessage(`{"use":"jwt-svid","kty":false,"priv":"not a key"}`), json.RawMessage(`{"use":"wit-svid","kty":"AKP","alg":"ML-DSA-65"}`), json.RawMessage(`{"use":"unknown","kty":"AKP"}`), json.RawMessage(`{"use":"x509-svid","kty":"future"}`))
	data, err = json.Marshal(doc)
	require.NoError(t, err)
	parsed, err := spiffebundle.ParseX509Only(td, data)
	require.NoError(t, err)
	require.True(t, original.Equal(parsed))
	require.Empty(t, parsed.JWTAuthorities())
	require.Empty(t, parsed.WITAuthorities())
	classical, err := spiffebundle.FromX509Bundle(test.NewCA(t, td).X509Bundle()).Marshal()
	require.NoError(t, err)
	_, err = spiffebundle.ParseX509Only(td, classical)
	require.ErrorContains(t, err, "classical X.509 authority")
}

func TestPQBundleDocumentRejectionAndEmptyTrust(t *testing.T) {
	for _, data := range []string{
		`{}`, `null`, `[]`, `{"keys":null}`, `{"keys":{}}`,
		`{"keys":[],"keys":[]}`, `{"keys":[],"\u006beys":[]}`,
		`{"keys":[],"spiffe_sequence":null}`, `{"keys":[],"spiffe_sequence":-1}`, `{"keys":[],"spiffe_sequence":18446744073709551616}`,
		`{"keys":[],"spiffe_refresh_hint":null}`, `{"keys":[],"spiffe_refresh_hint":-1}`, `{"keys":[],"spiffe_refresh_hint":9223372037}`, `{"keys":[],"spiffe_refresh_hint":1.5}`,
		`{"keys":[null]}`, `{"keys":[{"use":"x509-svid","kty":"AKP","kty":"RSA"}]}`,
		`{"keys":[]} {}`,
	} {
		parsed, err := spiffebundle.ParseX509Only(td, []byte(data))
		require.Error(t, err, "input: %s", data)
		require.Nil(t, parsed)
	}
	for _, data := range []string{`{"keys":[]}`, `{"keys":[{"use":"x509-svid","kty":"AKP"}]}`, `{"keys":[{"use":"x509-svid","kty":"AKP","x5c":[]}]}`} {
		parsed, err := spiffebundle.ParseX509Only(td, []byte(data))
		require.NoError(t, err)
		require.True(t, parsed.Empty())
	}
	empty := spiffebundle.New(td)
	data, err := empty.Marshal()
	require.NoError(t, err)
	require.JSONEq(t, `{"keys":[]}`, string(data))
	_, err = spiffebundle.ParseX509Only(spiffeid.TrustDomain{}, data)
	require.Error(t, err)
	for _, duration := range []time.Duration{-1, time.Duration(math.MaxInt64)} {
		empty.SetRefreshHint(duration)
		_, err = empty.Marshal()
		require.Error(t, err)
	}
}

func TestPQBundleSnapshotIsolationAndInvalidConstruction(t *testing.T) {
	cert := test.NewPQCA(t, td).X509Authorities()[0]
	encoded := bytes.Clone(cert.Raw)
	b := spiffebundle.FromX509Authorities(td, []*x509.Certificate{cert})
	xb := x509bundle.FromX509Authorities(td, []*x509.Certificate{cert})
	bClone, xbClone := b.Clone(), xb.Clone()
	cert.Raw[0] = 0
	cert.PublicKey = nil
	b.X509Authorities()[0].Raw[0] = 0
	xb.X509Authorities()[0].Raw[0] = 0
	require.Equal(t, encoded, b.X509Authorities()[0].Raw)
	require.True(t, b.Equal(bClone))
	require.True(t, xb.Equal(xbClone))
	for _, invalid := range []*x509.Certificate{nil, {}, {Raw: []byte("invalid")}} {
		b.SetX509Authorities([]*x509.Certificate{invalid})
		_, err := b.Marshal()
		require.Error(t, err)
		xb.SetX509Authorities([]*x509.Certificate{invalid})
		_, err = xb.Marshal()
		require.Error(t, err)
	}
	var nilBundle *spiffebundle.Bundle
	_, err := nilBundle.Marshal()
	require.Error(t, err)
	var nilX509 *x509bundle.Bundle
	_, err = nilX509.Marshal()
	require.Error(t, err)
}

func TestPQBundleConcurrentSnapshots(t *testing.T) {
	ca := test.NewPQCA(t, td)
	b := spiffebundle.FromX509Bundle(ca.X509Bundle())
	other := b.Clone()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				b.SetX509Authorities(ca.X509Authorities())
				b.SetSequenceNumber(uint64(j))
				_ = b.Equal(other)
				_ = b.Clone()
				_, err := b.GetX509BundleForTrustDomain(td)
				if err != nil {
					t.Error(err)
				}
				_, err = b.Marshal()
				if err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
}

func FuzzPQBundleReadX509Only(f *testing.F) {
	seed, err := spiffebundle.FromX509Bundle(test.NewPQCA(f, td).X509Bundle()).Marshal()
	require.NoError(f, err)
	f.Add(seed)
	f.Add([]byte(`{"keys":[]}`))
	f.Add([]byte(`{"keys":[],"keys":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := spiffebundle.ParseX509Only(td, data)
		if err != nil {
			require.Nil(t, b)
			return
		}
		require.Empty(t, b.JWTAuthorities())
		require.Empty(t, b.WITAuthorities())
		encoded, err := b.Marshal()
		require.NoError(t, err)
		decoded, err := spiffebundle.ParseX509Only(td, encoded)
		require.NoError(t, err)
		require.True(t, b.Equal(decoded))
		require.Equal(t, td, decoded.TrustDomain())
	})
}

func TestBundleLegacyMultipleCertificatesUseFirst(t *testing.T) {
	b, err := spiffebundle.Load(td, "testdata/spiffebundle_multiple_x509.json")
	require.NoError(t, err)
	require.Len(t, b.X509Authorities(), 1)
}
