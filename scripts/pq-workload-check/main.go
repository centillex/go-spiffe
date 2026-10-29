// pq-workload-check checks one live Workload API response. It is not an issuer,
// attestation verifier, or a complete step-6 acceptance runner.
package main

import (
	"context"
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
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type report struct {
	Status        string `json:"status"`
	Identity      string `json:"identity"`
	AnchorSHA256  string `json:"anchor_sha256"`
	ApprovedPaths int    `json:"approved_paths"`
	Step6Complete bool   `json:"step6_complete"`
}

func validateEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "unix" || u.Host != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !path.IsAbs(u.Path) {
		return errors.New("explicit absolute unix socket URL required")
	}
	return nil
}

func check(c *workloadapi.X509Context, expected spiffeid.ID, pin [32]byte) (*report, error) {
	if expected.IsZero() || expected.Path() == "" || c == nil || c.Bundles == nil || len(c.SVIDs) == 0 {
		return nil, errors.New("missing identity or credentials")
	}
	// Select exactly one requested identity, never silently use the first SVID.
	var selected *x509svid.SVID
	for _, s := range c.SVIDs {
		if s != nil && s.ID == expected {
			if selected != nil {
				return nil, errors.New("ambiguous identity")
			}
			selected = s
		}
	}
	if selected == nil {
		return nil, errors.New("requested identity not delivered")
	}
	bundle, err := c.Bundles.GetX509BundleForTrustDomain(expected.TrustDomain())
	if err != nil {
		return nil, errors.New("requested trust domain not delivered")
	}
	var anchors []*x509.Certificate
	for _, cert := range bundle.X509Authorities() {
		if cert != nil && sha256.Sum256(cert.Raw) == pin {
			anchors = append(anchors, cert)
		}
	}
	if len(anchors) == 0 {
		return nil, errors.New("externally provisioned anchor pin does not match")
	}
	// Verify using only the externally pinned authority, not all delivered roots.
	id, paths, err := x509svid.Verify(selected.Certificates, x509bundle.FromX509Authorities(expected.TrustDomain(), anchors))
	if err != nil || id != expected {
		return nil, errors.New("strict credential path verification failed")
	}
	return &report{Status: "credential_path_verified", Identity: id.String(), AnchorSHA256: hex.EncodeToString(pin[:]), ApprovedPaths: len(paths)}, nil
}

func run() error {
	endpoint := flag.String("endpoint", "", "explicit unix:///absolute/socket path")
	identity := flag.String("id", "", "expected workload SPIFFE ID")
	root := flag.String("anchor-sha256", "", "independently provisioned SHA-256 of exact anchor DER")
	timeout := flag.Duration("timeout", 10*time.Second, "finite Workload API timeout (maximum one minute)")
	flag.Parse()
	if err := validateEndpoint(*endpoint); err != nil {
		return err
	}
	if *timeout <= 0 || *timeout > time.Minute {
		return errors.New("timeout must be positive and at most one minute")
	}
	id, err := spiffeid.FromString(*identity)
	if err != nil || id.Path() == "" {
		return errors.New("valid non-root SPIFFE ID required")
	}
	decoded, err := hex.DecodeString(*root)
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("32-byte anchor digest required; no trust-on-first-use")
	}
	var pin [32]byte
	copy(pin[:], decoded)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	credentials, err := workloadapi.FetchX509Context(ctx, workloadapi.WithAddr(*endpoint))
	// Do not dump responses, certificates, keys, tokens, or backend error details.
	if err != nil {
		return errors.New("workload API fetch failed")
	}
	result, err := check(credentials, id, pin)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
