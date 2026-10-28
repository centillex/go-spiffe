package federation_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spiffe/go-spiffe/v2/federation"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/stretchr/testify/require"
)

type forbiddenDefaultTransport struct{ calls atomic.Int32 }

func (r *forbiddenDefaultTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls.Add(1)
	return nil, errors.New("mutable global transport must not be used")
}

func TestStrictPQFederationTransport(t *testing.T) {
	original := http.DefaultTransport
	global := &forbiddenDefaultTransport{}
	http.DefaultTransport = global
	t.Cleanup(func() { http.DefaultTransport = original; require.Zero(t, global.calls.Load()) })
	for _, pq := range []bool{true, false} {
		name := "classical rejected"
		if pq {
			name = "PQ authenticated"
		}
		t.Run(name, func(t *testing.T) {
			roots, cert := test.CreateWebCredentials(t)
			if pq {
				roots, cert = test.CreatePQWebCredentials(t)
			}
			// Transport authentication is distinct from step-5 payload admission.
			bundle := test.NewCA(t, td).Bundle()
			payload, err := bundle.Marshal()
			require.NoError(t, err)
			var requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); _, _ = w.Write(payload) }))
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*cert}}
			server.StartTLS()
			defer server.Close()
			got, err := federation.FetchBundle(context.Background(), td, server.URL, federation.WithWebPKIRoots(roots))
			if pq {
				require.NoError(t, err)
				require.NotNil(t, got)
				require.EqualValues(t, 1, requests.Load())
			} else {
				require.Error(t, err)
				require.Nil(t, got)
				require.Zero(t, requests.Load())
			}
		})
	}
}

func TestStrictPQFederationRejectsPlaintextAndRedirects(t *testing.T) {
	var plaintextRequests atomic.Int32
	plaintext := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { plaintextRequests.Add(1) }))
	defer plaintext.Close()
	_, err := federation.FetchBundle(context.Background(), td, plaintext.URL)
	require.ErrorContains(t, err, "must use HTTPS")
	require.Zero(t, plaintextRequests.Load())
	roots, cert := test.CreatePQWebCredentials(t)
	var target atomic.Value
	target.Store(plaintext.URL)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.Load().(string), http.StatusFound)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*cert}}
	server.StartTLS()
	defer server.Close()
	_, err = federation.FetchBundle(context.Background(), td, server.URL, federation.WithWebPKIRoots(roots))
	require.ErrorContains(t, err, "redirects are not permitted")
	require.Zero(t, plaintextRequests.Load())
	// Also reject secure redirects rather than silently changing endpoint identity.
	target.Store(strings.Replace(server.URL, "127.0.0.1", "localhost", 1))
	_, err = federation.FetchBundle(context.Background(), td, server.URL, federation.WithWebPKIRoots(roots))
	require.ErrorContains(t, err, "redirects are not permitted")
}
