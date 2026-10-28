package grpccredentials

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/pqpolicy"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// TLSClientCredentials returns TLS credentials which verify and authorize
// the server X509-SVID.
func TLSClientCredentials(bundle x509bundle.Source, authorizer tlsconfig.Authorizer, opts ...tlsconfig.Option) credentials.TransportCredentials {
	return credentialsWrapper{c: newOwnedCredentials(tlsconfig.TLSClientConfig(bundle, authorizer, opts...)), expectPeerID: true}
}

// MTLSClientCredentials returns TLS credentials which present an X509-SVID
// to the server and verifies and authorizes the server X509-SVID.
func MTLSClientCredentials(svid x509svid.Source, bundle x509bundle.Source, authorizer tlsconfig.Authorizer, opts ...tlsconfig.Option) credentials.TransportCredentials {
	return credentialsWrapper{c: newOwnedCredentials(tlsconfig.MTLSClientConfig(svid, bundle, authorizer, opts...)), expectPeerID: true, requireMutual: true}
}

// MTLSWebClientCredentials returns TLS credentials which present an X509-SVID
// to the server and verifies the server certificate using provided roots (or
// the system roots if nil).
func MTLSWebClientCredentials(svid x509svid.Source, roots *x509.CertPool, opts ...tlsconfig.Option) credentials.TransportCredentials {
	return credentialsWrapper{c: newOwnedCredentials(tlsconfig.MTLSWebClientConfig(svid, roots, opts...)), expectPeerID: false, requireMutual: true}
}

// TLSServerCredentials returns TLS credentials which present an X509-SVID
// to the client and does not require or verify client certificates.
func TLSServerCredentials(svid x509svid.Source, opts ...tlsconfig.Option) credentials.TransportCredentials {
	return credentialsWrapper{c: newOwnedCredentials(tlsconfig.TLSServerConfig(svid, opts...)), expectPeerID: false}
}

// MTLSServerCredentials returns TLS credentials which present an X509-SVID
// to the client and requires, verifies, and authorizes client X509-SVIDs.
func MTLSServerCredentials(svid x509svid.Source, bundle x509bundle.Source, authorizer tlsconfig.Authorizer, opts ...tlsconfig.Option) credentials.TransportCredentials {
	return credentialsWrapper{c: newOwnedCredentials(tlsconfig.MTLSServerConfig(svid, bundle, authorizer, opts...)), expectPeerID: true, requireMutual: true}
}

// MTLSWebServerCredentials returns TLS credentials which present a web
// server certificate to the client and requires, verifies, and authorizes
// client X509-SVIDs.
func MTLSWebServerCredentials(cert *tls.Certificate, bundle x509bundle.Source, authorizer tlsconfig.Authorizer, opts ...tlsconfig.Option) credentials.TransportCredentials {
	return credentialsWrapper{c: newOwnedCredentials(tlsconfig.MTLSWebServerConfig(cert, bundle, authorizer, opts...)), expectPeerID: true, requireMutual: true}
}

// PeerIDFromContext returns the SPIFFE ID from the peer information on the
// context. If the peer does not have a SPIFFE ID, or the credentials for the
// connection were not provided by this package, the function returns false.
func PeerIDFromContext(ctx context.Context) (spiffeid.ID, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return spiffeid.ID{}, false
	}
	return PeerIDFromPeer(p)
}

// PeerIDFromPeer returns the SPIFFE ID for the peer information on the
// context. If the peer does not have a SPIFFE ID, or the credentials for the
// connection were not provided by this package, the function returns false.
func PeerIDFromPeer(p *peer.Peer) (spiffeid.ID, bool) {
	authInfo, ok := p.AuthInfo.(authInfoWrapper)
	if !ok {
		return spiffeid.ID{}, false
	}
	return authInfo.PeerID()
}

type credentialsWrapper struct {
	c             credentials.TransportCredentials
	expectPeerID  bool
	requireMutual bool
}

func (w credentialsWrapper) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return w.wrapHandshake(w.c.ClientHandshake(ctx, authority, rawConn))
}

func (w credentialsWrapper) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return w.wrapHandshake(w.c.ServerHandshake(rawConn))
}

func (w credentialsWrapper) wrapHandshake(conn net.Conn, authInfo credentials.AuthInfo, handshakeErr error) (net.Conn, credentials.AuthInfo, error) {
	if handshakeErr != nil {
		return nil, nil, handshakeErr
	}
	tlsInfo, ok := authInfo.(credentials.TLSInfo)
	if !ok {
		conn.Close()
		return nil, nil, fmt.Errorf("expected TLS authentication information")
	}
	if w.requireMutual {
		if err := pqpolicy.CheckMutualTLS(tlsInfo.State); err != nil {
			conn.Close()
			return nil, nil, err
		}
	}
	var peerID spiffeid.ID
	if w.expectPeerID {
		if tlsInfo.SPIFFEID == nil {
			conn.Close()
			return nil, nil, fmt.Errorf("missing peer SPIFFE ID")
		}
		var err error
		peerID, err = spiffeid.FromString(tlsInfo.SPIFFEID.String())
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("invalid peer SPIFFE ID: %w", err)
		}
	}
	return conn, authInfoWrapper{AuthInfo: authInfo, peerID: peerID}, nil
}

func (w credentialsWrapper) Info() credentials.ProtocolInfo {
	return w.c.Info()
}

func (w credentialsWrapper) Clone() credentials.TransportCredentials {
	return credentialsWrapper{
		c:             w.c.Clone(),
		expectPeerID:  w.expectPeerID,
		requireMutual: w.requireMutual,
	}
}

func (w credentialsWrapper) OverrideServerName(serverName string) error {
	return w.c.OverrideServerName(serverName) // nolint:staticcheck // wrapper needs to call underlying method until fully deprecated
}

type authInfoWrapper struct {
	credentials.AuthInfo

	peerID spiffeid.ID
}

func (w authInfoWrapper) PeerID() (spiffeid.ID, bool) {
	return w.peerID, !w.peerID.IsZero()
}
