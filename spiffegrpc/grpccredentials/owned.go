package grpccredentials

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc/credentials"
)

type ownedCredentials struct {
	config     *tlsconfig.Config
	mu         sync.RWMutex
	serverName string
}

func newOwnedCredentials(config *tlsconfig.Config) credentials.TransportCredentials {
	return &ownedCredentials{config: config.WithALPN("h2")}
}
func (c *ownedCredentials) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	c.mu.RLock()
	name := c.serverName
	c.mu.RUnlock()
	if name == "" {
		name = authority
	}
	if host, _, err := net.SplitHostPort(name); err == nil {
		name = host
	}
	conn, err := c.config.Client(ctx, raw, name)
	return ownedAuthInfo(conn, err)
}
func (c *ownedCredentials) ServerHandshake(raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, err := c.config.Server(context.Background(), raw)
	return ownedAuthInfo(conn, err)
}
func ownedAuthInfo(conn *tlsconfig.Conn, err error) (net.Conn, credentials.AuthInfo, error) {
	if err != nil {
		return nil, nil, err
	}
	state := conn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		conn.Close()
		return nil, nil, fmt.Errorf("gRPC requires h2 ALPN")
	}
	info := credentials.TLSInfo{State: state, CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity}}
	if len(state.PeerCertificates) > 0 {
		if id, err := x509svid.IDFromCert(state.PeerCertificates[0]); err == nil {
			info.SPIFFEID = id.URL()
		}
	}
	return conn, info, nil
}
func (c *ownedCredentials) Info() credentials.ProtocolInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return credentials.ProtocolInfo{SecurityProtocol: "tls", SecurityVersion: "1.3", ServerName: c.serverName} //nolint:staticcheck // preserve TransportCredentials.Info/OverrideServerName compatibility
}
func (c *ownedCredentials) Clone() credentials.TransportCredentials {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return &ownedCredentials{config: c.config, serverName: c.serverName}
}
func (c *ownedCredentials) OverrideServerName(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.serverName = name
	return nil
}
