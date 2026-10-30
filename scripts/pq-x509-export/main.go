// pq-x509-export writes the public X.509 SVID chain and bundle from the
// Workload API as PEM files. It never writes private keys.
package main

import (
	"context"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func run() error {
	endpoint := flag.String("endpoint", "", "workload API address")
	dir := flag.String("dir", "", "output directory")
	timeout := flag.Duration("timeout", 10*time.Second, "fetch timeout")
	flag.Parse()
	if *endpoint == "" || *dir == "" {
		return errors.New("endpoint and dir are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(*endpoint))
	if err != nil {
		return errors.New("workload API client failed")
	}
	defer client.Close()
	x509Context, err := client.FetchX509Context(ctx)
	if err != nil {
		return errors.New("X.509 context fetch failed")
	}
	if len(x509Context.SVIDs) == 0 || x509Context.Bundles == nil {
		return errors.New("no X.509 credentials delivered")
	}
	if err := os.MkdirAll(*dir, 0700); err != nil {
		return err
	}

	svid := x509Context.SVIDs[0]
	chain, err := os.OpenFile(filepath.Join(*dir, "chain.pem"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer chain.Close()
	for _, cert := range svid.Certificates {
		if err := pem.Encode(chain, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return err
		}
	}

	bundle, err := x509Context.Bundles.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err != nil {
		return err
	}
	bundleFile, err := os.OpenFile(filepath.Join(*dir, "bundle.pem"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer bundleFile.Close()
	for _, cert := range bundle.X509Authorities() {
		if err := pem.Encode(bundleFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "wrote public X.509 chain and %d-authority bundle\n", len(bundle.X509Authorities()))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
