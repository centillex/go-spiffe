package tlsconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/pqpolicy"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// Config owns a strict-profile TLS configuration. It intentionally does not
// expose a *tls.Config or the underlying *tls.Conn. Its zero value is unusable.
// Config is safe for concurrent use; sources and callbacks must also be safe.
// This is a breaking replacement for constructors returning mutable tls.Config.
type Config struct {
	tls      *tls.Config
	server   bool
	mutual   bool
	registry *connRegistry
}

func (c *Config) validate(server bool) error {
	if c == nil || c.tls == nil || c.server != server {
		return profileError("invalid configuration role")
	}
	// ECH callbacks are not covered by this profile and may expose a raw
	// ClientHelloInfo.Conn or introduce a separate authentication path.
	if c.tls.GetEncryptedClientHelloKeys != nil || c.tls.EncryptedClientHelloRejectionVerify != nil || len(c.tls.EncryptedClientHelloKeys) != 0 || len(c.tls.EncryptedClientHelloConfigList) != 0 {
		return profileError("ECH configuration is unsupported")
	}
	return nil
}

// WithBaseTLSConfig snapshots transport preferences and additional verification
// callbacks. Authentication/protocol/session fields are overridden by policy.
// Later mutations of base cannot change the owned config. Do not mutate base
// concurrently with this call. Sources, callbacks and writers remain caller-owned.
func WithBaseTLSConfig(base *tls.Config) Option {
	snapshot := snapshotConfig(base)
	return option(func(o *options) { o.base = snapshot })
}

func ownedBase(opts []Option) *tls.Config {
	return snapshotConfig(newOptions(opts).base)
}

// TLSClientConfig authenticates and authorizes a server SVID (not mutual TLS).
func TLSClientConfig(bundle x509bundle.Source, authorizer Authorizer, opts ...Option) *Config {
	c := ownedBase(opts)
	hookTLSClientConfig(c, bundle, authorizer)
	return &Config{tls: c, registry: newConnRegistry()}
}

// MTLSClientConfig requires a completed mutual certificate exchange.
func MTLSClientConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) *Config {
	c := ownedBase(opts)
	hookMTLSClientConfig(c, svid, bundle, authorizer, opts...)
	return &Config{tls: c, mutual: true, registry: newConnRegistry()}
}

// WebClientConfig authenticates a PQ Web PKI server, including its hostname.
func WebClientConfig(roots *x509.CertPool, opts ...Option) *Config {
	c := ownedBase(opts)
	resetAuthFields(c)
	if roots != nil {
		c.RootCAs = roots.Clone()
	}
	installConnectionPolicy(c, nil, nil, x509.ExtKeyUsageServerAuth, false, true, false)
	return &Config{tls: c, registry: newConnRegistry()}
}

// MTLSWebClientConfig requires mutual TLS with a PQ Web PKI server.
func MTLSWebClientConfig(svid x509svid.Source, roots *x509.CertPool, opts ...Option) *Config {
	c := ownedBase(opts)
	if roots != nil {
		roots = roots.Clone()
	}
	hookMTLSWebClientConfig(c, svid, roots, opts...)
	return &Config{tls: c, mutual: true, registry: newConnRegistry()}
}

// TLSServerConfig presents a server SVID without client authentication.
func TLSServerConfig(svid x509svid.Source, opts ...Option) *Config {
	c := ownedBase(opts)
	hookTLSServerConfig(c, svid, opts...)
	return &Config{tls: c, server: true, registry: newConnRegistry()}
}

// MTLSServerConfig requires and authorizes a client SVID.
func MTLSServerConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) *Config {
	c := ownedBase(opts)
	hookMTLSServerConfig(c, svid, bundle, authorizer, opts...)
	return &Config{tls: c, server: true, mutual: true, registry: newConnRegistry()}
}

// WebServerConfig presents a PQ Web PKI credential without client authentication.
func WebServerConfig(cert *tls.Certificate, opts ...Option) *Config {
	c := ownedBase(opts)
	resetAuthFields(c)
	if cert != nil {
		copy := snapshotCertificate(*cert)
		cert = &copy
	}
	c.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if cert == nil {
			return nil, profileError("nil Web PKI credential")
		}
		copy := snapshotCertificate(*cert)
		if err := validateLocalKey(&copy); err != nil {
			return nil, err
		}
		return &copy, nil
	}
	installConnectionPolicy(c, nil, nil, x509.ExtKeyUsageClientAuth, true, false, true)
	return &Config{tls: c, server: true, registry: newConnRegistry()}
}

// MTLSWebServerConfig presents a PQ Web PKI credential and authorizes client SVIDs.
func MTLSWebServerConfig(cert *tls.Certificate, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) *Config {
	c := ownedBase(opts)
	if cert != nil {
		copy := snapshotCertificate(*cert)
		cert = &copy
	}
	hookMTLSWebServerConfig(c, cert, bundle, authorizer)
	return &Config{tls: c, server: true, mutual: true, registry: newConnRegistry()}
}

// WithALPN returns an independent config with the supplied application protocols.
// This cannot change TLS/authentication/session policy.
func (c *Config) WithALPN(protocols ...string) *Config {
	if c == nil || c.tls == nil {
		return &Config{}
	}
	copy := *c
	if copy.registry == nil {
		copy.registry = newConnRegistry()
	}
	copy.tls = snapshotConfig(c.tls)
	copy.tls.NextProtos = append([]string(nil), protocols...)
	return &copy
}

// Client takes ownership of raw, completes authentication, and only then returns
// a connection. On failure it closes raw. serverName is used for Web PKI/SNI
// unless a name was supplied in the base config. SPIFFE authorization is separate.
func (c *Config) Client(ctx context.Context, raw net.Conn, serverName string) (*Conn, error) {
	if err := c.validate(false); err != nil {
		if raw != nil {
			raw.Close()
		}
		return nil, err
	}
	if raw == nil {
		return nil, profileError("invalid client configuration or connection")
	}
	config := snapshotConfig(c.tls)
	if config.ServerName == "" {
		config.ServerName = serverName
	}
	conn := &Conn{tls: tls.Client(raw, config), raw: raw, mutual: c.mutual, registry: c.registry}
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}

// Server takes ownership of raw and completes authentication before returning it.
func (c *Config) Server(ctx context.Context, raw net.Conn) (*Conn, error) {
	if err := c.validate(true); err != nil {
		if raw != nil {
			raw.Close()
		}
		return nil, err
	}
	if raw == nil {
		return nil, profileError("invalid server configuration or connection")
	}
	conn := &Conn{tls: tls.Server(raw, c.tls), raw: raw, mutual: c.mutual, registry: c.registry}
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}

// DialContext dials and authenticates an owned client connection. It can be used
// directly as http.Transport.DialTLSContext (HTTP/1.1).
func (c *Config) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if ctx == nil {
		return nil, profileError("nil dial context")
	}
	if err := c.validate(false); err != nil {
		return nil, err
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return c.Client(ctx, raw, host)
}

// Listener wraps an inner listener. Accepted connections authenticate on the
// first Handshake, Read or Write, and never release application data beforehand.
func (c *Config) Listener(inner net.Listener) (net.Listener, error) {
	if err := c.validate(true); err != nil {
		return nil, err
	}
	if inner == nil {
		return nil, profileError("invalid server configuration or listener")
	}
	return &ownedListener{Listener: inner, config: c}, nil
}

type ownedListener struct {
	net.Listener
	config *Config
}

func (l *ownedListener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err == nil && raw == nil {
		err = profileError("listener returned a nil connection")
	}
	if err != nil {
		return nil, err
	}
	return &Conn{tls: tls.Server(raw, l.config.tls), raw: raw, mutual: l.config.mutual, registry: l.config.registry}, nil
}

// Conn is a policy-checked net.Conn. It exposes neither raw socket nor mutable
// TLS config. Handshake and application I/O share a single final policy decision.
// Credential expiry bounds I/O; Config.RetireExpired/RetireAll provide explicit closure.
// See docs/LIFECYCLE.md for the synchronization guarantees.
type Conn struct {
	tls          *tls.Conn
	raw          net.Conn
	mutual       bool
	once         sync.Once
	handshakeErr error

	registry  *connRegistry
	expiresAt time.Time
	closeOnce sync.Once
}

func (c *Conn) Handshake() error { return c.HandshakeContext(context.Background()) }
func (c *Conn) HandshakeContext(ctx context.Context) error {
	if c == nil || c.tls == nil {
		return profileError("uninitialized connection")
	}
	c.once.Do(func() {
		if ctx == nil {
			c.handshakeErr = profileError("nil handshake context")
		} else {
			c.handshakeErr = c.tls.HandshakeContext(ctx)
		}
		if c.handshakeErr == nil {
			state := c.tls.ConnectionState()
			c.handshakeErr = pqpolicy.CheckTLS(state)
			if c.handshakeErr == nil && c.mutual {
				c.handshakeErr = pqpolicy.CheckMutualTLS(state)
			}
		}
		if c.handshakeErr != nil {
			_ = c.raw.Close()
		} else {
			c.expiresAt = credentialDeadline(c.tls.ConnectionState())
			c.registry.add(c, c.expiresAt)
			// Bound application I/O by credential expiry so a connection
			// cannot outlive the credentials that authenticated it. Callers
			// can still close it proactively or retire it via RetireExpired.
			if !c.expiresAt.IsZero() {
				_ = c.raw.SetDeadline(c.expiresAt)
			}
		}
	})
	return c.handshakeErr
}
func (c *Conn) Read(p []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	return c.tls.Read(p)
}
func (c *Conn) Write(p []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	return c.tls.Write(p)
}
func (c *Conn) Close() error {
	if c == nil || c.tls == nil {
		return net.ErrClosed
	}
	return c.closeUnderlying()
}

// closeUnderlying closes the TLS connection at most once and unregisters it.
func (c *Conn) closeUnderlying() error {
	var err error
	first := false
	c.closeOnce.Do(func() {
		first = true
		c.registry.remove(c)
		err = c.tls.Close()
	})
	if !first {
		return net.ErrClosed
	}
	return err
}
func (c *Conn) LocalAddr() net.Addr {
	if c == nil || c.tls == nil {
		return nil
	}
	return c.tls.LocalAddr()
}
func (c *Conn) RemoteAddr() net.Addr {
	if c == nil || c.tls == nil {
		return nil
	}
	return c.tls.RemoteAddr()
}
func (c *Conn) SetDeadline(t time.Time) error {
	if c == nil || c.tls == nil {
		return net.ErrClosed
	}
	return c.tls.SetDeadline(c.capDeadline(t))
}
func (c *Conn) SetReadDeadline(t time.Time) error {
	if c == nil || c.tls == nil {
		return net.ErrClosed
	}
	return c.tls.SetReadDeadline(c.capDeadline(t))
}
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.tls == nil {
		return net.ErrClosed
	}
	return c.tls.SetWriteDeadline(c.capDeadline(t))
}

// capDeadline prevents callers from extending I/O past credential expiry.
func (c *Conn) capDeadline(t time.Time) time.Time {
	if c.expiresAt.IsZero() {
		return t
	}
	if t.IsZero() || t.After(c.expiresAt) {
		return c.expiresAt
	}
	return t
}

// ConnectionState returns detached certificate/byte slices, not mutable internal state.
func (c *Conn) ConnectionState() tls.ConnectionState {
	if c == nil || c.tls == nil {
		return tls.ConnectionState{}
	}
	return snapshotState(c.tls.ConnectionState())
}
