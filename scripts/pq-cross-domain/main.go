// pq-cross-domain authenticates two workloads in separate trust domains using
// the SDK's owned strict-profile TLS transports and the live Workload API.
// It is integration evidence, not a production application.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
	mode := flag.String("mode", "", "client or server")
	socket := flag.String("socket", "", "workload API unix socket")
	addr := flag.String("addr", "127.0.0.1:18450", "application TCP address")
	id := flag.String("id", "", "this workload's expected SPIFFE ID")
	peer := flag.String("peer", "", "expected peer SPIFFE ID")
	timeout := flag.Duration("timeout", 20*time.Second, "operation timeout")
	flag.Parse()
	if err := run(*mode, *socket, *addr, *id, *peer, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(mode, socket, addr, selfID, peerID string, timeout time.Duration) error {
	if mode != "client" && mode != "server" {
		return errors.New("mode must be client or server")
	}
	self, err := spiffeid.FromString(selfID)
	if err != nil {
		return errors.New("invalid self ID")
	}
	peer, err := spiffeid.FromString(peerID)
	if err != nil {
		return errors.New("invalid peer ID")
	}
	if socket == "" {
		return errors.New("socket required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+strings.TrimPrefix(socket, "unix://"))))
	if err != nil {
		return fmt.Errorf("credential source: %w", err)
	}
	defer source.Close()
	svid, err := source.GetX509SVID()
	if err != nil {
		return fmt.Errorf("svid: %w", err)
	}
	if svid.ID != self {
		return fmt.Errorf("unexpected local identity %s", svid.ID)
	}
	// Federated bundles propagate asynchronously from the server to the agent.
	if err := waitForBundle(ctx, source, peer); err != nil {
		return err
	}

	if mode == "server" {
		cfg := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeID(peer))
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		defer listener.Close()
		fmt.Println("READY")
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		owned, err := cfg.Server(ctx, conn)
		if err != nil {
			return fmt.Errorf("server handshake: %w", err)
		}
		defer owned.Close()
		reader := bufio.NewReader(owned)
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		if strings.TrimSpace(line) != "PING" {
			return errors.New("unexpected application data")
		}
		if _, err := owned.Write([]byte("PONG\n")); err != nil {
			return err
		}
		state := owned.ConnectionState()
		fmt.Printf("SERVER_OK peer=%s tls=%s kex=%s\n", peerID, version(state.Version), state.CurveID)
		return nil
	}

	raw, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	cfg := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(peer))
	conn, err := cfg.Client(ctx, raw, "")
	if err != nil {
		return fmt.Errorf("client handshake: %w", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("PING\n")); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if strings.TrimSpace(line) != "PONG" {
		return errors.New("unexpected application response")
	}
	state := conn.ConnectionState()
	if state.Version != 0x0304 {
		return fmt.Errorf("unexpected TLS version %x", state.Version)
	}
	fmt.Printf("CLIENT_OK peer=%s tls=%s kex=%s\n", peerID, version(state.Version), state.CurveID)
	return nil
}

func waitForBundle(ctx context.Context, source *workloadapi.X509Source, peer spiffeid.ID) error {
	for {
		if _, err := source.GetX509BundleForTrustDomain(peer.TrustDomain()); err == nil {
			return nil
		}
		if err := source.WaitUntilUpdated(ctx); err != nil {
			return fmt.Errorf("peer trust domain bundle unavailable: %w", err)
		}
	}
}

func version(v uint16) string {
	if v == 0x0304 {
		return "TLS1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}
