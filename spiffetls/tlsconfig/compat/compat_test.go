package compat_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"

	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig/compat"
	"github.com/stretchr/testify/require"
)

func handshake(t *testing.T, server, client *tls.Config) (*tls.Conn, error, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	serverCh := make(chan *tls.Conn, 1)
	serverErr := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		conn := tls.Server(raw, server)
		serverCh <- conn
		serverErr <- conn.HandshakeContext(context.Background())
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	clientConn := tls.Client(raw, client)
	clientErr := clientConn.HandshakeContext(context.Background())
	serverConn := <-serverCh
	_ = clientConn
	return serverConn, <-serverErr, clientErr
}

func TestMutualTLSWithUpstreamSignatures(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	serverSVID := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/server"))
	clientSVID := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/client"))

	server := compat.MTLSServerConfig(serverSVID, ca.X509Bundle(), compat.AuthorizeID(clientSVID.ID))
	client := compat.MTLSClientConfig(clientSVID, ca.X509Bundle(), compat.AuthorizeID(serverSVID.ID))

	serverConn, serverErr, clientErr := handshake(t, server, client)
	require.NoError(t, serverErr)
	require.NoError(t, clientErr)
	defer serverConn.Close()

	id, err := spiffetls.PeerIDFromConnectionState(serverConn.ConnectionState())
	require.NoError(t, err)
	require.Equal(t, clientSVID.ID, id)
}

func TestHookInstallsPolicy(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))

	client := &tls.Config{}
	compat.HookMTLSClientConfig(client, svid, ca.X509Bundle(), compat.AuthorizeID(svid.ID))
	require.NotNil(t, client.GetClientCertificate)
	require.NotNil(t, client.VerifyConnection)
	require.True(t, client.InsecureSkipVerify)
}

func TestVerifyPeerCertificateAuthorizer(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
	raw := svid.Certificates[0].Raw

	verify := compat.VerifyPeerCertificate(ca.X509Bundle(), compat.AuthorizeID(svid.ID))
	require.NoError(t, verify([][]byte{raw}, nil))

	verify = compat.VerifyPeerCertificate(ca.X509Bundle(), compat.AuthorizeID(spiffeid.RequireFromPath(td, "/other")))
	require.Error(t, verify([][]byte{raw}, nil))
}

func TestCompatibilityConfigRejectsDowngrade(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	serverSVID := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/server"))
	clientSVID := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/client"))

	server := compat.MTLSServerConfig(serverSVID, ca.X509Bundle(), compat.AuthorizeID(clientSVID.ID))
	client := compat.MTLSClientConfig(clientSVID, ca.X509Bundle(), compat.AuthorizeID(serverSVID.ID))
	client.MinVersion = tls.VersionTLS12
	client.MaxVersion = tls.VersionTLS12

	_, serverErr, clientErr := handshake(t, server, client)
	require.Error(t, serverErr)
	require.Error(t, clientErr)
}
