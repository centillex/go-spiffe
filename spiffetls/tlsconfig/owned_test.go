package tlsconfig_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/stretchr/testify/require"
)

func ownedHandshake(t *testing.T, server, client *tlsconfig.Config) (*tlsconfig.Conn, *tlsconfig.Conn, error, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	b, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	a, err := ln.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = a.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type result struct {
		conn *tlsconfig.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() { c, e := server.Server(ctx, a); done <- result{c, e} }()
	c, ce := client.Client(ctx, b, "127.0.0.1")
	s := <-done
	return s.conn, c, s.err, ce
}

func TestOwnedMutualTLSAndSnapshot(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
	base := &tls.Config{MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"test"}}
	option := tlsconfig.WithBaseTLSConfig(base)
	client := tlsconfig.MTLSClientConfig(svid, ca.X509Bundle(), tlsconfig.AuthorizeID(svid.ID), option)
	server := tlsconfig.MTLSServerConfig(svid, ca.X509Bundle(), tlsconfig.AuthorizeID(svid.ID), option)
	// Mutating the input, including callbacks and aliased slices, cannot affect either owner.
	base.NextProtos[0] = "changed"
	base.CurvePreferences[0] = tls.CurveP256
	base.VerifyConnection = func(tls.ConnectionState) error { return errors.New("must not run") }
	_, conn, se, ce := ownedHandshake(t, server, client)
	require.NoError(t, se)
	require.NoError(t, ce)
	state := conn.ConnectionState()
	require.Equal(t, "test", state.NegotiatedProtocol)
	require.NotEmpty(t, state.LocalCertificate)
	require.NotEmpty(t, state.PeerCertificates)
	state.PeerCertificates[0].URIs[0].Host = "untrusted.example"
	state.PeerCertificates[0].Raw[0] = 0
	require.Equal(t, "pq.example", conn.ConnectionState().PeerCertificates[0].URIs[0].Host)
	_, exposesRaw := any(conn).(interface{ NetConn() net.Conn })
	require.False(t, exposesRaw)
	typ := reflect.TypeFor[tlsconfig.Config]()
	for i := 0; i < typ.NumField(); i++ {
		require.False(t, typ.Field(i).IsExported())
	}
}

func TestOwnedMutualTLSApprovedGroups(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	serverSVID := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/server"))
	clientSVID := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/client"))
	roots := x509.NewCertPool()
	roots.AddCert(ca.X509Authorities()[0])
	for _, group := range []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768} {
		t.Run(group.String(), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()
			b, err := net.Dial("tcp", ln.Addr().String())
			require.NoError(t, err)
			defer b.Close()
			a, err := ln.Accept()
			require.NoError(t, err)
			defer a.Close()
			require.NoError(t, a.SetDeadline(time.Now().Add(3*time.Second)))
			cert := tls.Certificate{PrivateKey: serverSVID.PrivateKey}
			for _, c := range serverSVID.Certificates {
				cert.Certificate = append(cert.Certificate, c.Raw)
			}
			native := tls.Server(a, &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, Certificates: []tls.Certificate{cert}, CurvePreferences: []tls.CurveID{group}})
			done := make(chan error, 1)
			go func() { done <- native.Handshake() }()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			client := tlsconfig.MTLSClientConfig(clientSVID, ca.X509Bundle(), tlsconfig.AuthorizeID(serverSVID.ID))
			conn, err := client.Client(ctx, b, "")
			require.NoError(t, err)
			require.NoError(t, <-done)
			require.Equal(t, group, conn.ConnectionState().CurveID)
			require.Equal(t, clientSVID.ID.URL(), native.ConnectionState().PeerCertificates[0].URIs[0])
		})
	}
}

func TestOwnedWebConfigsAndTrustSnapshot(t *testing.T) {
	roots, cert := test.CreatePQWebCredentials(t)
	server, client := tlsconfig.WebServerConfig(cert), tlsconfig.WebClientConfig(roots)
	cert.Certificate[0][0] = 0 // caller mutation must not change the owned credential
	_, c, se, ce := ownedHandshake(t, server, client)
	require.NoError(t, se)
	require.NoError(t, ce)
	require.NotNil(t, c)
	other := test.NewPQCA(t, spiffeid.RequireTrustDomainFromString("other.example"))
	leafs, key := other.CreateX509Certificate(test.WithIPAddresses(net.ParseIP("127.0.0.1")))
	otherCert := &tls.Certificate{PrivateKey: key}
	for _, leaf := range leafs {
		otherCert.Certificate = append(otherCert.Certificate, leaf.Raw)
	}
	roots.AddCert(other.X509Authorities()[0]) // client has already snapshotted trust
	_, _, _, ce = ownedHandshake(t, tlsconfig.WebServerConfig(otherCert), client)
	require.ErrorContains(t, ce, "unknown authority")
}

func TestOwnedClientRequiresMutualExchange(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
	server := tlsconfig.TLSServerConfig(svid)
	client := tlsconfig.MTLSClientConfig(svid, ca.X509Bundle(), tlsconfig.AuthorizeAny())
	s, c, se, ce := ownedHandshake(t, server, client)
	require.NoError(t, se)
	require.ErrorContains(t, ce, "mutual certificate exchange")
	require.Nil(t, c)
	require.NoError(t, s.SetReadDeadline(time.Now().Add(time.Second)))
	var b [1]byte
	n, err := s.Read(b[:])
	require.Error(t, err)
	require.Zero(t, n)
}

func TestOwnedCallbacksAreAdditionalAndIsolated(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
	for _, deny := range []bool{false, true} {
		t.Run(map[bool]string{false: "isolated mutations", true: "caller may reject"}[deny], func(t *testing.T) {
			sentinel := errors.New("callback rejection")
			base := &tls.Config{VerifyPeerCertificate: func(raw [][]byte, chains [][]*x509.Certificate) error { //nolint:gosec // input callback is wrapped by the owned constructor
				raw[0][0] = 0
				chains[0][0].URIs[0].Host = "not-the-peer"
				return nil
			}, VerifyConnection: func(state tls.ConnectionState) error {
				state.PeerCertificates[0].URIs[0].Host = "not-the-peer"
				if deny {
					return sentinel
				}
				return nil
			}}
			server := tlsconfig.MTLSServerConfig(svid, ca.X509Bundle(), tlsconfig.AuthorizeAny())
			client := tlsconfig.MTLSClientConfig(svid, ca.X509Bundle(), tlsconfig.AuthorizeAny(), tlsconfig.WithBaseTLSConfig(base))
			_, c, se, ce := ownedHandshake(t, server, client)
			if deny {
				require.ErrorIs(t, ce, sentinel)
				require.Nil(t, c)
			} else {
				require.NoError(t, se)
				require.NoError(t, ce)
				require.Equal(t, svid.ID.URL().Host, c.ConnectionState().PeerCertificates[0].URIs[0].Host)
			}
		})
	}
}

func TestOwnedLazyListenerRejectsBeforeWrite(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer raw.Close()
	server := tlsconfig.MTLSServerConfig(svid, ca.X509Bundle(), tlsconfig.AuthorizeID(spiffeid.RequireFromPath(td, "/not-authorized")))
	listener, err := server.Listener(raw)
	require.NoError(t, err)
	defer listener.Close()
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, e := listener.Accept()
		if e != nil {
			done <- result{err: e}
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		n, e := c.Write([]byte("must not escape"))
		done <- result{n, e}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := tlsconfig.MTLSClientConfig(svid, ca.X509Bundle(), tlsconfig.AuthorizeID(svid.ID))
	conn, clientErr := client.DialContext(ctx, "tcp", listener.Addr().String())
	if clientErr == nil {
		defer conn.Close()
		require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
		var b [32]byte
		n, e := conn.Read(b[:])
		require.Zero(t, n)
		require.Error(t, e)
	}
	r := <-done
	require.Zero(t, r.n)
	require.ErrorContains(t, r.err, "unexpected ID")
}

func TestOwnedCanceledHandshakeClosesSocket(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, b.SetReadDeadline(time.Now().Add(time.Second)))
	conn, err := tlsconfig.WebClientConfig(nil).Client(ctx, a, "localhost")
	require.Nil(t, conn)
	require.ErrorIs(t, err, context.Canceled)
	var buf [1]byte
	n, err := b.Read(buf[:])
	require.Zero(t, n)
	require.ErrorIs(t, err, io.EOF)
}

func TestOwnedTraceAndAuthorizationBoundaries(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
	server := tlsconfig.MTLSServerConfig(svid, ca.X509Bundle(), tlsconfig.AuthorizeAny())
	observed := false
	trace := tlsconfig.Trace{GotCertificate: func(info tlsconfig.GotCertificateInfo, _ any) {
		if info.Err != nil {
			return
		}
		observed = true
		require.Nil(t, info.Cert.PrivateKey, "tracing must not expose signing material")
		info.Cert.Certificate[0][0] = 0
		info.Cert.Leaf.URIs[0].Host = "not-the-peer"
	}}
	client := tlsconfig.MTLSClientConfig(svid, ca.X509Bundle(), tlsconfig.AuthorizeAny(), tlsconfig.WithTrace(trace))
	_, c, se, ce := ownedHandshake(t, server, client)
	require.NoError(t, se)
	require.NoError(t, ce)
	require.NotNil(t, c)
	require.True(t, observed)
	called := false
	base := &tls.Config{VerifyConnection: func(tls.ConnectionState) error { called = true; return nil }}
	client = tlsconfig.MTLSClientConfig(svid, ca.X509Bundle(), tlsconfig.AuthorizeID(spiffeid.RequireFromPath(td, "/wrong")), tlsconfig.WithBaseTLSConfig(base))
	_, c, _, ce = ownedHandshake(t, server, client)
	require.Error(t, ce)
	require.Nil(t, c)
	require.False(t, called)
}

func TestOwnedRejectsUnsupportedECHAndZeroValues(t *testing.T) {
	called := false
	base := &tls.Config{GetEncryptedClientHelloKeys: func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) { called = true; return nil, nil }}
	config := tlsconfig.WebClientConfig(nil, tlsconfig.WithBaseTLSConfig(base))
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_, err := config.Client(context.Background(), a, "localhost")
	require.ErrorContains(t, err, "ECH configuration is unsupported")
	require.False(t, called)
	var zero tlsconfig.Config
	_, err = zero.DialContext(context.Background(), "tcp", "127.0.0.1:1")
	require.Error(t, err)
	var conn tlsconfig.Conn
	_, err = conn.Write([]byte{1})
	require.Error(t, err)
	require.Error(t, conn.Close())
	require.False(t, conn.ConnectionState().HandshakeComplete)
}

func TestOwnedRejectsAlternateConfigAndLegacyCallbacks(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
	called := false
	base := &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { called = true; return &tls.Config{}, nil }}
	server := tlsconfig.MTLSServerConfig(svid, ca.X509Bundle(), tlsconfig.AuthorizeAny(), tlsconfig.WithBaseTLSConfig(base))
	client := tlsconfig.MTLSClientConfig(svid, ca.X509Bundle(), tlsconfig.AuthorizeAny())
	_, _, se, ce := ownedHandshake(t, server, client)
	require.ErrorContains(t, se, "GetConfigForClient overrides")
	require.Error(t, ce)
	require.False(t, called)
	require.ErrorIs(t, tlsconfig.VerifyPeerCertificate(ca.X509Bundle(), tlsconfig.AuthorizeAny())(nil, nil), tlsconfig.ErrUnsupportedAPI)                                //nolint:staticcheck // verify deprecated APIs fail closed
	wrapped := tlsconfig.WrapVerifyPeerCertificate(func([][]byte, [][]*x509.Certificate) error { called = true; return nil }, ca.X509Bundle(), tlsconfig.AuthorizeAny()) //nolint:staticcheck // verify deprecated APIs fail closed
	require.ErrorIs(t, wrapped(nil, nil), tlsconfig.ErrUnsupportedAPI)
	require.False(t, called)
	hooks := []func(*tls.Config){
		func(c *tls.Config) { tlsconfig.HookTLSClientConfig(c, nil, nil) },          //nolint:staticcheck // retired API rejection
		func(c *tls.Config) { tlsconfig.HookMTLSClientConfig(c, nil, nil, nil) },    //nolint:staticcheck // retired API rejection
		func(c *tls.Config) { tlsconfig.HookMTLSWebClientConfig(c, nil, nil) },      //nolint:staticcheck // retired API rejection
		func(c *tls.Config) { tlsconfig.HookTLSServerConfig(c, nil) },               //nolint:staticcheck // retired API rejection
		func(c *tls.Config) { tlsconfig.HookMTLSServerConfig(c, nil, nil, nil) },    //nolint:staticcheck // retired API rejection
		func(c *tls.Config) { tlsconfig.HookMTLSWebServerConfig(c, nil, nil, nil) }, //nolint:staticcheck // retired API rejection
	}
	for _, hook := range hooks {
		raw := &tls.Config{}
		hook(raw)
		require.ErrorIs(t, raw.VerifyConnection(tls.ConnectionState{}), tlsconfig.ErrUnsupportedAPI)
		_, err := raw.GetConfigForClient(nil)
		require.ErrorIs(t, err, tlsconfig.ErrUnsupportedAPI)
	}
}
