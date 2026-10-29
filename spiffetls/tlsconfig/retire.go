package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"
)

type tlsConnectionState = tls.ConnectionState
type x509Certificate = x509.Certificate

func parseCertificate(der []byte) (*x509.Certificate, error) { return x509.ParseCertificate(der) }

// connRegistry tracks authenticated owned connections so callers can retire
// those whose credentials expired or whose trust was removed. Retirement is
// explicit or periodically driven by the caller; it is not an instant
// revocation mechanism.
type connRegistry struct {
	mu    sync.Mutex
	conns map[*Conn]time.Time
}

func newConnRegistry() *connRegistry {
	return &connRegistry{conns: make(map[*Conn]time.Time)}
}

func (r *connRegistry) add(conn *Conn, expiresAt time.Time) {
	if r == nil || conn == nil {
		return
	}
	r.mu.Lock()
	r.conns[conn] = expiresAt
	r.mu.Unlock()
}

func (r *connRegistry) remove(conn *Conn) {
	if r == nil || conn == nil {
		return
	}
	r.mu.Lock()
	delete(r.conns, conn)
	r.mu.Unlock()
}

func (r *connRegistry) count() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.conns)
}

// retire closes connections matching the predicate. Connections are removed
// from the registry before being closed so concurrent retirement cannot close
// the same connection twice.
func (r *connRegistry) retire(match func(expiresAt time.Time) bool) int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	var victims []*Conn
	for conn, expiresAt := range r.conns {
		if match(expiresAt) {
			victims = append(victims, conn)
			delete(r.conns, conn)
		}
	}
	r.mu.Unlock()

	for _, conn := range victims {
		_ = conn.closeUnderlying()
	}
	return len(victims)
}

// RetireExpired closes owned connections whose local or peer credential has
// expired at or before now. It returns the number of connections closed. A
// connection with no known deadline is left alone; use RetireAll for trust
// removal or manual rotation.
func (c *Config) RetireExpired(now time.Time) int {
	if c == nil {
		return 0
	}
	return c.registry.retire(func(expiresAt time.Time) bool {
		return !expiresAt.IsZero() && !expiresAt.After(now)
	})
}

// RetireAll closes every owned connection tracked by this configuration. It is
// intended for callers that have removed trust or rotated credentials and want
// established connections to stop being used. It returns the number closed.
func (c *Config) RetireAll() int {
	if c == nil {
		return 0
	}
	return c.registry.retire(func(time.Time) bool { return true })
}

// ActiveConnections reports how many authenticated connections are still
// tracked by this configuration.
func (c *Config) ActiveConnections() int {
	if c == nil {
		return 0
	}
	return c.registry.count()
}

// ExpiresAt reports the credential deadline of the connection: the earliest
// NotAfter among the presented local chain and the verified peer chain. The
// zero value means no deadline could be determined.
func (c *Conn) ExpiresAt() time.Time {
	if c == nil {
		return time.Time{}
	}
	return c.expiresAt
}

// credentialDeadline returns the earliest credential expiry in the connection
// state, or the zero time if none can be determined.
func credentialDeadline(state tlsConnectionState) time.Time {
	var deadline time.Time
	consider := func(cert *x509Certificate) {
		if cert == nil || cert.NotAfter.IsZero() {
			return
		}
		if deadline.IsZero() || cert.NotAfter.Before(deadline) {
			deadline = cert.NotAfter
		}
	}
	for _, cert := range state.PeerCertificates {
		consider(cert)
	}
	for _, der := range state.LocalCertificate {
		cert, err := parseCertificate(der)
		if err == nil {
			consider(cert)
		}
	}
	return deadline
}
