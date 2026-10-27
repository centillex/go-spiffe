package grpccredentials_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/stretchr/testify/require"
)

func TestStrictPQGRPCCredentials(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("pq.example")
	ca := test.NewPQCA(t, td)
	server := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/server"))
	client := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/client"))
	for _, mutual := range []bool{true, false} {
		name := "server-only rejected by mTLS client"
		if mutual {
			name = "mutual success"
		}
		t.Run(name, func(t *testing.T) {
			sc := grpccredentials.TLSServerCredentials(server)
			if mutual {
				sc = grpccredentials.MTLSServerCredentials(server, ca.X509Bundle(), tlsconfig.AuthorizeID(client.ID))
			}
			cc := grpccredentials.MTLSClientCredentials(client, ca.X509Bundle(), tlsconfig.AuthorizeID(server.ID)).Clone()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			rawClient, err := net.Dial("tcp", listener.Addr().String())
			require.NoError(t, err)
			defer rawClient.Close()
			rawServer, err := listener.Accept()
			require.NoError(t, err)
			defer rawServer.Close()
			require.NoError(t, rawServer.SetDeadline(time.Now().Add(3*time.Second)))
			done := make(chan error, 1)
			go func() { _, _, err := sc.ServerHandshake(rawServer); done <- err }()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, info, clientErr := cc.ClientHandshake(ctx, "pq.example", rawClient)
			serverErr := <-done
			if mutual {
				require.NoError(t, clientErr)
				require.NoError(t, serverErr)
				require.NotNil(t, info)
			} else {
				require.ErrorContains(t, clientErr, "mutual certificate exchange")
			}
		})
	}
}
