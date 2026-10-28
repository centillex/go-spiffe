package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

func strictHandshake(t *testing.T, server, client *tls.Config) (tls.ConnectionState, error, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	b, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer b.Close()
	a, err := listener.Accept()
	require.NoError(t, err)
	defer a.Close()
	require.NoError(t, a.SetDeadline(time.Now().Add(3*time.Second)))
	require.NoError(t, b.SetDeadline(time.Now().Add(3*time.Second)))
	s, c := tls.Server(a, server), tls.Client(b, client)
	done := make(chan error, 1)
	go func() {
		err := s.Handshake()
		if err != nil {
			_ = a.Close()
		}
		done <- err
	}()
	ce := c.Handshake()
	if ce != nil {
		_ = b.Close()
	}
	se := <-done
	return c.ConnectionState(), se, ce
}

func TestStrictPQHandshake(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	child := ca.ChildCA()
	server := child.CreateX509SVID(spiffeid.RequireFromPath(td, "/server"))
	client := child.CreateX509SVID(spiffeid.RequireFromPath(td, "/client"))
	for _, group := range []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768} {
		t.Run(group.String(), func(t *testing.T) {
			sc := nativeMTLSServerConfig(server, ca.X509Bundle(), AuthorizeID(client.ID))
			cc := nativeMTLSClientConfig(client, ca.X509Bundle(), AuthorizeID(server.ID))
			sc.CurvePreferences = []tls.CurveID{group}
			cc.CurvePreferences = []tls.CurveID{group}
			state, se, ce := strictHandshake(t, sc, cc)
			require.NoError(t, se)
			require.NoError(t, ce)
			require.Equal(t, tls.VersionTLS13, int(state.Version))
			require.Equal(t, group, state.CurveID)
			require.False(t, state.DidResume)
		})
	}
}

func TestStrictPQRejectsDowngrades(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	server := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/server"))
	client := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/client"))
	cases := []struct {
		name   string
		change func(*tls.Config, *tls.Config)
	}{
		{"classical group", func(s, c *tls.Config) {
			s.CurvePreferences = []tls.CurveID{tls.X25519}
			c.CurvePreferences = []tls.CurveID{tls.X25519}
		}},
		{"unapproved PQ group", func(s, c *tls.Config) {
			s.CurvePreferences = []tls.CurveID{tls.MLKEM1024}
			c.CurvePreferences = []tls.CurveID{tls.MLKEM1024}
		}},
		{"TLS12", func(s, c *tls.Config) { s.MaxVersion = tls.VersionTLS12; c.MaxVersion = tls.VersionTLS12 }},
		{"missing client certificate", func(_, c *tls.Config) { c.GetClientCertificate = nil }},
		{"authorization", func(s, _ *tls.Config) {
			hookMTLSServerConfig(s, server, ca.X509Bundle(), AuthorizeID(server.ID))
		}},
		{"classical peer", func(s, c *tls.Config) {
			classicCA := test.NewCA(t, td)
			classic := classicCA.CreateX509SVID(server.ID)
			*s = tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{classic.Certificates[0].Raw}, PrivateKey: classic.PrivateKey}}}
			*c = *nativeTLSClientConfig(classicCA.X509Bundle(), AuthorizeAny())
		}},
		{"classical source", func(s, _ *tls.Config) {
			classical := test.NewCA(t, td).CreateX509SVID(server.ID)
			s.GetCertificate = GetCertificate(classical)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := nativeMTLSServerConfig(server, ca.X509Bundle(), AuthorizeAny())
			cc := nativeMTLSClientConfig(client, ca.X509Bundle(), AuthorizeAny())
			tc.change(sc, cc)
			_, se, ce := strictHandshake(t, sc, cc)
			require.True(t, se != nil || ce != nil, "both peers accepted invalid connection")
		})
	}
}

type countedSessionCache struct{ accesses atomic.Int32 }

func (c *countedSessionCache) Get(string) (*tls.ClientSessionState, bool) {
	c.accesses.Add(1)
	return nil, false
}
func (c *countedSessionCache) Put(string, *tls.ClientSessionState) { c.accesses.Add(1) }

func TestStrictPQDisablesSessionCache(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
	cache := &countedSessionCache{}
	cc := &tls.Config{ClientSessionCache: cache, ServerName: "pq.example"}
	hookMTLSClientConfig(cc, svid, ca.X509Bundle(), AuthorizeAny())
	sc := nativeMTLSServerConfig(svid, ca.X509Bundle(), AuthorizeAny())
	for range 2 {
		state, se, ce := strictHandshake(t, sc, cc)
		require.NoError(t, se)
		require.NoError(t, ce)
		require.False(t, state.DidResume)
	}
	require.Zero(t, cache.accesses.Load())
}

func TestStrictPQWebPKI(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	client := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/client"))
	certs, key := ca.CreateX509Certificate(test.WithIPAddresses(net.ParseIP("127.0.0.1")))
	roots := x509.NewCertPool()
	roots.AddCert(ca.X509Authorities()[0])
	cert := &tls.Certificate{PrivateKey: key}
	for _, c := range certs {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	sc := nativeMTLSWebServerConfig(cert, ca.X509Bundle(), AuthorizeAny())
	cc := nativeMTLSWebClientConfig(client, roots)
	cc.ServerName = "127.0.0.1"
	_, se, ce := strictHandshake(t, sc, cc)
	require.NoError(t, se)
	require.NoError(t, ce)

	classicalRoots, classicalCert := test.CreateWebCredentials(t)
	weak := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*classicalCert}}
	cc = nativeMTLSWebClientConfig(client, classicalRoots)
	cc.ServerName = "127.0.0.1"
	_, _, ce = strictHandshake(t, weak, cc)
	require.ErrorContains(t, ce, "no approved Web PKI certification path")
}

func TestStrictPQOverridesAndCallbacks(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
	called := false
	config := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.X25519}, ClientSessionCache: tls.NewLRUClientSessionCache(1), GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { called = true; return &tls.Config{}, nil }} //nolint:gosec // deliberately weak input; the hook must replace it
	hookMTLSServerConfig(config, svid, ca.X509Bundle(), AuthorizeAny())
	require.Equal(t, uint16(tls.VersionTLS13), config.MinVersion)
	require.Equal(t, uint16(tls.VersionTLS13), config.MaxVersion)
	require.True(t, config.SessionTicketsDisabled)
	require.Nil(t, config.ClientSessionCache)
	_, err := config.GetConfigForClient(nil)
	require.Error(t, err)
	require.False(t, called)
	require.Error(t, config.VerifyConnection(tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.X25519MLKEM768, DidResume: true}))
	require.Error(t, config.VerifyConnection(tls.ConnectionState{Version: tls.VersionTLS13, CurveID: tls.X25519MLKEM768}))

	sentinel := errors.New("caller rejects")
	peerCalled := false
	cc := &tls.Config{VerifyPeerCertificate: func(_ [][]byte, chains [][]*x509.Certificate) error { //nolint:gosec // legacy input callback must be wrapped in VerifyConnection
		peerCalled = true
		require.NotEmpty(t, chains)
		return sentinel
	}}
	hookMTLSClientConfig(cc, svid, ca.X509Bundle(), AuthorizeAny())
	sc := nativeMTLSServerConfig(svid, ca.X509Bundle(), AuthorizeAny())
	_, _, err = strictHandshake(t, sc, cc)
	require.ErrorIs(t, err, sentinel)
	require.True(t, peerCalled)
}
