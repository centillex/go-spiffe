package tlsconfig_test

import (
	"context"
	"crypto/x509"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"
)

type staticSVID struct{ svid *x509svid.SVID }

func (s staticSVID) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }

type staticBundle struct{ bundle *x509bundle.Bundle }

func (s staticBundle) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if s.bundle.TrustDomain() != td {
		return nil, errNoBundle
	}
	return s.bundle, nil
}

type fixedError string

func (e fixedError) Error() string { return string(e) }

const errNoBundle = fixedError("no bundle")

func exchange(t *testing.T, server, client *tlsconfig.Config) (*tlsconfig.Conn, *tlsconfig.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	clientRaw, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	serverRaw, err := listener.Accept()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		conn *tlsconfig.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() { conn, err := server.Server(ctx, serverRaw); done <- result{conn, err} }()
	clientConn, clientErr := client.Client(ctx, clientRaw, "127.0.0.1")
	serverResult := <-done
	require.NoError(t, serverResult.err)
	require.NoError(t, clientErr)
	return serverResult.conn, clientConn
}

func TestRetireAllClosesAuthenticatedConnections(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	serverID := spiffeid.RequireFromPath(td, "/server")
	clientID := spiffeid.RequireFromPath(td, "/client")
	ca := test.NewPQCA(t, td)
	serverSVID := ca.CreateX509SVID(serverID)
	clientSVID := ca.CreateX509SVID(clientID)
	bundle := staticBundle{bundle: ca.X509Bundle()}

	serverCfg := tlsconfig.MTLSServerConfig(staticSVID{svid: serverSVID}, bundle, tlsconfig.AuthorizeID(clientID))
	clientCfg := tlsconfig.MTLSClientConfig(staticSVID{svid: clientSVID}, bundle, tlsconfig.AuthorizeID(serverID))

	serverConn, clientConn := exchange(t, serverCfg, clientCfg)
	require.Equal(t, 1, serverCfg.ActiveConnections())
	require.Equal(t, 1, clientCfg.ActiveConnections())

	// The connection works before retirement.
	require.NoError(t, serverConn.SetDeadline(time.Now().Add(time.Second)))
	_, err := clientConn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = serverConn.Read(buf)
	require.NoError(t, err)

	// Retirement closes both ends that this side owns.
	require.Equal(t, 1, serverCfg.RetireAll())
	require.Equal(t, 0, serverCfg.ActiveConnections())
	// The client side still tracks its own connection until it is retired.
	require.Equal(t, 1, clientCfg.RetireAll())

	readErr := make(chan error, 1)
	go func() {
		_, err := clientConn.Read(buf)
		readErr <- err
	}()
	select {
	case err := <-readErr:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("retired connection remained usable")
	}

	// Closing an already retired connection reports closed.
	require.Error(t, serverConn.Close())
}

func TestRetireExpiredOnlyClosesPastDeadline(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	serverID := spiffeid.RequireFromPath(td, "/server")
	clientID := spiffeid.RequireFromPath(td, "/client")
	ca := test.NewPQCA(t, td)
	serverSVID := ca.CreateX509SVID(serverID)
	clientSVID := ca.CreateX509SVID(clientID)
	bundle := staticBundle{bundle: ca.X509Bundle()}

	serverCfg := tlsconfig.MTLSServerConfig(staticSVID{svid: serverSVID}, bundle, tlsconfig.AuthorizeID(clientID))
	clientCfg := tlsconfig.MTLSClientConfig(staticSVID{svid: clientSVID}, bundle, tlsconfig.AuthorizeID(serverID))
	serverConn, _ := exchange(t, serverCfg, clientCfg)

	deadline := serverConn.ExpiresAt()
	require.False(t, deadline.IsZero(), "connection must expose a credential deadline")

	// Nothing to retire before the deadline.
	require.Equal(t, 0, serverCfg.RetireExpired(deadline.Add(-time.Minute)))
	require.Equal(t, 1, serverCfg.ActiveConnections())

	// At the deadline the connection is retired.
	require.Equal(t, 1, serverCfg.RetireExpired(deadline))
	require.Equal(t, 0, serverCfg.ActiveConnections())

	require.Equal(t, 1, clientCfg.RetireAll())
}

func TestCloseUnregistersConnection(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	serverID := spiffeid.RequireFromPath(td, "/server")
	clientID := spiffeid.RequireFromPath(td, "/client")
	ca := test.NewPQCA(t, td)
	bundle := staticBundle{bundle: ca.X509Bundle()}

	serverCfg := tlsconfig.MTLSServerConfig(staticSVID{svid: ca.CreateX509SVID(serverID)}, bundle, tlsconfig.AuthorizeID(clientID))
	clientCfg := tlsconfig.MTLSClientConfig(staticSVID{svid: ca.CreateX509SVID(clientID)}, bundle, tlsconfig.AuthorizeID(serverID))
	serverConn, clientConn := exchange(t, serverCfg, clientCfg)

	require.Equal(t, 1, serverCfg.ActiveConnections())
	require.NoError(t, serverConn.Close())
	require.Equal(t, 0, serverCfg.ActiveConnections())
	require.Equal(t, 0, serverCfg.RetireAll())
	require.NoError(t, clientConn.Close())
}

func TestTrustRemovalRejectsNewHandshake(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	otherTD := spiffeid.RequireTrustDomainFromString("other.test")
	serverID := spiffeid.RequireFromPath(td, "/server")
	clientID := spiffeid.RequireFromPath(td, "/client")
	ca := test.NewPQCA(t, td)

	// A source whose trust can be withdrawn between handshakes.
	source := &swappableBundle{set: x509bundle.NewSet(ca.X509Bundle())}
	serverCfg := tlsconfig.MTLSServerConfig(staticSVID{svid: ca.CreateX509SVID(serverID)}, source, tlsconfig.AuthorizeID(clientID))
	clientCfg := tlsconfig.MTLSClientConfig(staticSVID{svid: ca.CreateX509SVID(clientID)}, source, tlsconfig.AuthorizeID(serverID))

	serverConn, clientConn := exchange(t, serverCfg, clientCfg)
	require.NoError(t, serverConn.Close())
	require.NoError(t, clientConn.Close())
	require.Equal(t, 0, serverCfg.ActiveConnections())

	// Withdraw trust: new handshakes must fail, with no classical fallback.
	source.set = x509bundle.NewSet(x509bundle.FromX509Authorities(otherTD, []*x509.Certificate{ca.X509Authorities()[0]}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	clientRaw, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	serverRaw, err := listener.Accept()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverErr := make(chan error, 1)
	go func() {
		_, err := serverCfg.Server(ctx, serverRaw)
		serverErr <- err
	}()
	_, err = clientCfg.Client(ctx, clientRaw, "127.0.0.1")
	require.Error(t, err)
	require.Error(t, <-serverErr)
}

type swappableBundle struct {
	mu  sync.Mutex
	set *x509bundle.Set
}

func (s *swappableBundle) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.set.GetX509BundleForTrustDomain(td)
}

// TestConnectionIOStoppedAtCredentialExpiry verifies that I/O cannot outlive the
// credentials that authenticated the connection, even without proactive
// retirement.
func TestConnectionIOStoppedAtCredentialExpiry(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	serverID := spiffeid.RequireFromPath(td, "/server")
	clientID := spiffeid.RequireFromPath(td, "/client")
	ca := test.NewPQCA(t, td)
	now := time.Now()
	serverSVID := ca.CreateX509SVID(serverID, test.WithLifetime(now.Add(-time.Minute), now.Add(2*time.Second)))
	clientSVID := ca.CreateX509SVID(clientID, test.WithLifetime(now.Add(-time.Minute), now.Add(2*time.Second)))
	bundle := staticBundle{bundle: ca.X509Bundle()}

	serverCfg := tlsconfig.MTLSServerConfig(staticSVID{svid: serverSVID}, bundle, tlsconfig.AuthorizeID(clientID))
	clientCfg := tlsconfig.MTLSClientConfig(staticSVID{svid: clientSVID}, bundle, tlsconfig.AuthorizeID(serverID))
	serverConn, clientConn := exchange(t, serverCfg, clientCfg)
	defer serverConn.Close()
	defer clientConn.Close()

	deadline := clientConn.ExpiresAt()
	require.False(t, deadline.IsZero())
	require.True(t, deadline.Before(now.Add(5*time.Second)))

	time.Sleep(time.Until(deadline) + 150*time.Millisecond)

	// Callers cannot extend the deadline beyond credential expiry.
	require.NoError(t, clientConn.SetDeadline(time.Now().Add(time.Hour)))
	_, err := clientConn.Write([]byte("after-expiry"))
	require.Error(t, err)

	require.Equal(t, 1, serverCfg.RetireExpired(time.Now()))
	require.Equal(t, 1, clientCfg.RetireExpired(time.Now()))
}
