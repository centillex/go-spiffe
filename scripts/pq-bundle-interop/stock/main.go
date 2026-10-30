// Command stock-interop verifies a PQ X.509-SVID chain with the stock
// (unforked) go-spiffe module and a PEM bundle produced by pq-bundle-bridge.
// It proves the dual-format strategy is consumable outside the PQ fork.
package main

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

type report struct {
	Verified             bool   `json:"verified"`
	Identity             string `json:"identity"`
	SignatureAlgorithm   string `json:"signature_algorithm"`
	PublicKeyAlgorithm   string `json:"public_key_algorithm"`
	AuthorityCount       int    `json:"authority_count"`
	Consumer             string `json:"consumer"`
}

func run() error {
	chainPath := flag.String("chain", "", "PEM certificate chain")
	bundlePath := flag.String("bundle", "", "PEM trust bundle")
	identity := flag.String("id", "", "expected SPIFFE ID")
	trustDomain := flag.String("td", "", "expected trust domain")
	flag.Parse()

	if *chainPath == "" || *bundlePath == "" || *identity == "" || *trustDomain == "" {
		return errors.New("-chain, -bundle, -id and -td are required")
	}
	id, err := spiffeid.FromString(*identity)
	if err != nil {
		return fmt.Errorf("invalid identity: %w", err)
	}
	td, err := spiffeid.TrustDomainFromString(*trustDomain)
	if err != nil {
		return fmt.Errorf("invalid trust domain: %w", err)
	}
	chain, err := readCerts(*chainPath)
	if err != nil {
		return err
	}
	roots, err := readCerts(*bundlePath)
	if err != nil {
		return err
	}
	if len(chain) == 0 || len(roots) == 0 {
		return errors.New("chain and bundle must contain certificates")
	}

	bundle := x509bundle.FromX509Authorities(td, roots)
	verified, _, err := x509svid.Verify(chain, bundle)
	if err != nil {
		return fmt.Errorf("stock go-spiffe verification failed: %w", err)
	}
	if verified != id {
		return fmt.Errorf("verified identity %q does not match %q", verified, id)
	}
	leaf := chain[0]
	if _, ok := leaf.PublicKey.(*mldsa.PublicKey); !ok {
		return errors.New("leaf public key is not ML-DSA")
	}
	if leaf.SignatureAlgorithm != x509.MLDSA65 {
		return fmt.Errorf("unexpected leaf signature algorithm %v", leaf.SignatureAlgorithm)
	}

	return json.NewEncoder(os.Stdout).Encode(report{
		Verified:           true,
		Identity:           verified.String(),
		SignatureAlgorithm: leaf.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: leaf.PublicKeyAlgorithm.String(),
		AuthorityCount:     len(roots),
		Consumer:           "go-spiffe v2.9.0 (stock)",
	})
}

func readCerts(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	block, rest := pem.Decode(data)
	for block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		block, rest = pem.Decode(rest)
	}
	return certs, nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
