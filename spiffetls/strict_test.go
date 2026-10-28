package spiffetls_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestStrictPQConvenience(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
	for _, mutual := range []bool{true, false} {
		name := "reject server-only"
		if mutual {
			name = "mutual"
		}
		t.Run(name, func(t *testing.T) {
			serverMode := spiffetls.TLSServerWithRawConfig(svid)
			if mutual {
				serverMode = spiffetls.MTLSServerWithRawConfig(tlsconfig.AuthorizeAny(), svid, ca.X509Bundle())
			}
			base := &tls.Config{MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.X25519}}
			listener, err := spiffetls.ListenWithMode(context.Background(), "tcp", "127.0.0.1:0", serverMode, spiffetls.WithListenTLSConfigBase(base))
			require.NoError(t, err)
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					// Listener returns lazy TLS connections; trigger the handshake with Read.
					var b [1]byte
					_, err = conn.Read(b[:])
				}
				done <- err
			}()
			clientMode := spiffetls.MTLSClientWithRawConfig(tlsconfig.AuthorizeAny(), svid, ca.X509Bundle())
			conn, err := spiffetls.DialWithMode(context.Background(), "tcp", listener.Addr().String(), clientMode, spiffetls.WithDialer(&net.Dialer{Timeout: 3 * time.Second}), spiffetls.WithDialTLSConfigBase(base))
			if mutual {
				require.NoError(t, err)
				_, err = conn.Write([]byte{1})
				require.NoError(t, err)
				require.NoError(t, conn.Close())
				require.NoError(t, <-done)
			} else {
				require.ErrorContains(t, err, "mutual certificate exchange")
				require.Error(t, <-done) // rejected client closes without sending application data
			}
			require.Equal(t, uint16(tls.VersionTLS12), base.MinVersion, "caller base must not be mutated")
			require.Equal(t, []tls.CurveID{tls.X25519}, base.CurvePreferences)
		})
	}
}
