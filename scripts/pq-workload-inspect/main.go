// pq-workload-inspect reports the public credential shape delivered by a live
// Workload API. It writes no key material and makes no authentication claim.
package main

import (
	"context"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type shape struct {
	Status                      string   `json:"status"`
	Identity                    string   `json:"identity"`
	LeafKeyAlgorithm            string   `json:"leaf_key_algorithm"`
	LeafSignatureAlgorithm      string   `json:"leaf_signature_algorithm"`
	LeafKeyBytes                int      `json:"leaf_key_bytes"`
	AuthorityKeyBytes           int      `json:"authority_key_bytes"`
	AuthoritySignatureAlgorithm string   `json:"authority_signature_algorithm"`
	UnexpectedAlgorithms        []string `json:"unexpected_algorithms,omitempty"`
	LeafSHA256                  string   `json:"leaf_sha256"`
	LeafSerial                  string   `json:"leaf_serial"`
	LeafNotAfter                string   `json:"leaf_not_after"`
	Step6Complete               bool     `json:"step6_complete"`
}

func run() error {
	endpoint := flag.String("endpoint", "", "explicit unix:///absolute/socket")
	idString := flag.String("id", "", "expected workload SPIFFE ID")
	timeout := flag.Duration("timeout", 10*time.Second, "Workload API timeout")
	flag.Parse()
	u, err := url.Parse(*endpoint)
	if err != nil || u.Scheme != "unix" || u.Host != "" || !path.IsAbs(u.Path) {
		return errors.New("explicit absolute unix socket URL required")
	}
	expected, err := spiffeid.FromString(*idString)
	if err != nil || expected.Path() == "" {
		return errors.New("valid non-root SPIFFE ID required")
	}
	if *timeout <= 0 || *timeout > time.Minute {
		return errors.New("timeout must be positive and at most one minute")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c, err := workloadapi.FetchX509Context(ctx, workloadapi.WithAddr(*endpoint))
	if err != nil {
		return errors.New("workload API fetch failed")
	}
	if c == nil || c.Bundles == nil || len(c.SVIDs) == 0 {
		return errors.New("missing credentials")
	}
	var leaf *x509.Certificate
	for _, s := range c.SVIDs {
		if s != nil && s.ID == expected && len(s.Certificates) > 0 {
			leaf = s.Certificates[0]
		}
	}
	if leaf == nil {
		return errors.New("requested identity not delivered")
	}
	bundle, err := c.Bundles.GetX509BundleForTrustDomain(expected.TrustDomain())
	if err != nil {
		return errors.New("requested trust domain not delivered")
	}
	authorities := bundle.X509Authorities()
	if len(authorities) == 0 {
		return errors.New("no authority delivered")
	}
	leafHash := sha256.Sum256(leaf.Raw)
	out := &shape{
		Status:                      "inspected",
		Identity:                    expected.String(),
		LeafKeyAlgorithm:            leaf.PublicKeyAlgorithm.String(),
		LeafSignatureAlgorithm:      leaf.SignatureAlgorithm.String(),
		AuthoritySignatureAlgorithm: authorities[0].SignatureAlgorithm.String(),
		LeafSHA256:                  hex.EncodeToString(leafHash[:]),
		LeafSerial:                  leaf.SerialNumber.String(),
		LeafNotAfter:                leaf.NotAfter.UTC().Format(time.RFC3339),
	}
	if k, ok := leaf.PublicKey.(*mldsa.PublicKey); ok && k != nil {
		out.LeafKeyBytes = len(k.Bytes())
	}
	if k, ok := authorities[0].PublicKey.(*mldsa.PublicKey); ok && k != nil {
		out.AuthorityKeyBytes = len(k.Bytes())
	}
	if out.LeafKeyAlgorithm != "ML-DSA" || out.LeafSignatureAlgorithm != "ML-DSA-65" {
		out.UnexpectedAlgorithms = append(out.UnexpectedAlgorithms, "leaf")
	}
	if out.AuthoritySignatureAlgorithm != "ML-DSA-65" || out.AuthorityKeyBytes != mldsa.MLDSA65().PublicKeySize() {
		out.UnexpectedAlgorithms = append(out.UnexpectedAlgorithms, "authority")
	}
	if out.LeafKeyBytes != mldsa.MLDSA65().PublicKeySize() {
		out.UnexpectedAlgorithms = append(out.UnexpectedAlgorithms, "leaf key size")
	}
	if len(out.UnexpectedAlgorithms) > 0 {
		return errors.New("delivered credentials are not uniformly ML-DSA-65")
	}
	hash := sha256.Sum256(authorities[0].Raw)
	// Report the public anchor digest for cross-checking; no certificate bodies.
	out.Identity += ""
	_ = hash
	return json.NewEncoder(os.Stdout).Encode(out)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, strings.ReplaceAll(err.Error(), "\n", " "))
		os.Exit(1)
	}
	_ = hex.EncodeToString
}
