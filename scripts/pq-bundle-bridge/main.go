// pq-bundle-bridge converts between the AKP SPIFFE bundle JSON used by the PQ
// fork and a standard PEM X.509 bundle that stock SPIRE/go-spiffe can load.
// The PEM form carries X.509 authorities only; JWT/WIT authorities have no
// certificate representation and are reported as dropped.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	in := flag.String("in", "", "input bundle path")
	out := flag.String("out", "", "output bundle path")
	format := flag.String("out-format", "pem", "output format: pem or spiffe")
	trustDomain := flag.String("trust-domain", "", "trust domain for parsing/conversion")
	flag.Parse()

	if *in == "" || *out == "" || *trustDomain == "" {
		return errors.New("-in, -out and -trust-domain are required")
	}
	td, err := spiffeid.TrustDomainFromString(*trustDomain)
	if err != nil {
		return fmt.Errorf("invalid trust domain: %w", err)
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	switch *format {
	case "pem":
		bundle, err := spiffebundle.Parse(td, data)
		if err != nil {
			return fmt.Errorf("parse SPIFFE bundle: %w", err)
		}
		certs := bundle.X509Authorities()
		if len(certs) == 0 {
			return errors.New("bundle has no X.509 authorities to bridge")
		}
		file, err := os.OpenFile(*out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		defer file.Close()
		for _, cert := range certs {
			if _, ok := cert.PublicKey.(*mldsa.PublicKey); !ok {
				return errors.New("bundle contains a non-ML-DSA X.509 authority")
			}
			if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
				return fmt.Errorf("encode certificate: %w", err)
			}
		}
		fmt.Fprintf(os.Stderr, "bridged %d X.509 authorities to PEM; token authorities are not representable in PEM\n", len(certs))
		return nil
	case "spiffe":
		block, rest := pem.Decode(data)
		var certs []*x509.Certificate
		for block != nil {
			if block.Type != "CERTIFICATE" {
				return fmt.Errorf("unexpected PEM block %q", block.Type)
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("parse certificate: %w", err)
			}
			if _, ok := cert.PublicKey.(*mldsa.PublicKey); !ok {
				return errors.New("PEM bundle contains a non-ML-DSA certificate")
			}
			if cert.SignatureAlgorithm != x509.MLDSA65 {
				return fmt.Errorf("certificate signature algorithm %v is not ML-DSA-65", cert.SignatureAlgorithm)
			}
			certs = append(certs, cert)
			block, rest = pem.Decode(rest)
		}
		if len(certs) == 0 {
			return errors.New("PEM bundle contains no certificates")
		}
		bundle := spiffebundle.FromX509Authorities(td, certs)
		encoded, err := bundle.Marshal()
		if err != nil {
			return fmt.Errorf("marshal SPIFFE bundle: %w", err)
		}
		if err := os.WriteFile(*out, encoded, 0600); err != nil { //nolint:gosec // explicit CLI output path
			return fmt.Errorf("write output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "bridged %d X.509 authorities to AKP JSON\n", len(certs))
		return nil
	default:
		return fmt.Errorf("unsupported output format %q", *format)
	}
}
