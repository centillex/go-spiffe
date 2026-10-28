package tlsconfig

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/stretchr/testify/require"
)

type replayCache struct {
	mu    sync.Mutex
	state *tls.ClientSessionState
	gets  int
}

func (c *replayCache) Get(string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gets++
	return c.state, c.state != nil
}
func (c *replayCache) Put(_ string, s *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = s
}
func (c *replayCache) snapshot() (*tls.ClientSessionState, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state, c.gets
}

// nativeSessionExchange is a deliberately pre-policy native Go control. No
// session bytes, tickets, keys, or credentials are written to logs or disk.
func nativeSessionExchange(t *testing.T, server, client *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
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
	require.NoError(t, b.SetDeadline(time.Now().Add(3*time.Second)))
	s, c := tls.Server(a, server), tls.Client(b, client)
	done := make(chan error, 1)
	go func() {
		err := s.Handshake()
		if err == nil {
			_, err = s.Write([]byte{1})
		}
		done <- err
	}()
	err = c.Handshake()
	if err == nil {
		var marker [1]byte
		_, err = io.ReadFull(c, marker[:])
	}
	if err != nil {
		_ = b.Close()
	}
	serverErr := <-done
	if err == nil {
		err = serverErr
	}
	return c.ConnectionState(), err
}

func TestStrictPQSerializedPrePolicySessions(t *testing.T) {
	for _, pq := range []bool{false, true} {
		name := "classical credentials and group"
		if pq {
			name = "PQ credentials with pre-policy classical group"
		}
		t.Run(name, func(t *testing.T) {
			roots, cert := test.CreateWebCredentials(t)
			if pq {
				roots, cert = test.CreatePQWebCredentials(t)
			}
			cache := &replayCache{}
			server := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{*cert}, CurvePreferences: []tls.CurveID{tls.X25519, tls.X25519MLKEM768}}
			client := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1", ClientSessionCache: cache, CurvePreferences: []tls.CurveID{tls.X25519}}
			first, err := nativeSessionExchange(t, server, client)
			require.NoError(t, err)
			require.False(t, first.DidResume)
			require.Equal(t, tls.X25519, first.CurveID)
			original, _ := cache.snapshot()
			require.NotNil(t, original, "control must receive a real ticket")
			ticket, state, err := original.ResumptionState()
			require.NoError(t, err)
			encoded, err := state.Bytes()
			require.NoError(t, err)
			parsed, err := tls.ParseSessionState(encoded)
			require.NoError(t, err)
			restored, err := tls.NewResumptionState(ticket, parsed)
			require.NoError(t, err)
			replay := &replayCache{state: restored}
			control := client.Clone()
			control.ClientSessionCache = replay
			second, err := nativeSessionExchange(t, server, control)
			require.NoError(t, err)
			require.True(t, second.DidResume, "serialized session must be resumable in control")

			replay.Put("", restored)
			strict := WebClientConfig(roots, WithBaseTLSConfig(control))
			_, before := replay.snapshot()
			// Exercise the actual owned Client against the same session-ticket issuer.
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()
			done := make(chan error, 1)
			go func() {
				raw, e := ln.Accept()
				if e != nil {
					done <- e
					return
				}
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
				s := tls.Server(raw, server)
				e = s.Handshake()
				if e == nil {
					_, e = s.Write([]byte{1})
				}
				done <- e
			}()
			raw, err := net.Dial("tcp", ln.Addr().String())
			require.NoError(t, err)
			defer raw.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, strictErr := strict.Client(ctx, raw, "127.0.0.1")
			if pq {
				require.NoError(t, strictErr)
				require.False(t, conn.ConnectionState().DidResume)
				require.Equal(t, tls.X25519MLKEM768, conn.ConnectionState().CurveID)
				var b [1]byte
				_, err = io.ReadFull(conn, b[:])
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, strictErr, "no approved Web PKI certification path")
			}
			serverErr := <-done
			if pq {
				require.NoError(t, serverErr)
			}
			_, after := replay.snapshot()
			require.Equal(t, before, after, "strict owner must not consult pre-policy cache")

			// Defense in depth: even if a private native config is misconfigured in a
			// future refactor to enable resumption, VerifyConnection must reject it.
			replay.Put("", restored)
			forced := strict.tls.Clone()
			forced.SessionTicketsDisabled = false
			forced.ClientSessionCache = replay
			_, err = nativeSessionExchange(t, server, forced)
			require.ErrorContains(t, err, "session resumption is disabled")
		})
	}
}
