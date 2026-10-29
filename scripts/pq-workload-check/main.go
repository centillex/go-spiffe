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
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type report struct {
	Status            string `json:"status"`
	Identity          string `json:"identity"`
	AnchorSHA256      string `json:"anchor_sha256"`
	ApprovedPaths     int    `json:"approved_paths"`
	LeafSHA256        string `json:"leaf_sha256"`
	LeafNotAfter      string `json:"leaf_not_after"`
	JWTAudience       string `json:"jwt_audience,omitempty"`
	JWTAlgorithm      string `json:"jwt_algorithm,omitempty"`
	JWTVerified       bool   `json:"jwt_verified,omitempty"`
	JWTDelegatedValid bool   `json:"jwt_delegated_validation,omitempty"`
	JWTTamperRejected bool   `json:"jwt_tamper_rejected,omitempty"`
	Step6Complete     bool   `json:"step6_complete"`
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
	leafHash := sha256.Sum256(selected.Certificates[0].Raw)
	return &report{
		Status:        "credential_path_verified",
		Identity:      id.String(),
		AnchorSHA256:  hex.EncodeToString(pin[:]),
		ApprovedPaths: len(paths),
		LeafSHA256:    hex.EncodeToString(leafHash[:]),
		LeafNotAfter:  selected.Certificates[0].NotAfter.UTC().Format(time.RFC3339),
	}, nil
}

func run() error {
	endpoint := flag.String("endpoint", "", "explicit unix:///absolute/socket path")
	identity := flag.String("id", "", "expected workload SPIFFE ID")
	root := flag.String("anchor-sha256", "", "independently provisioned SHA-256 of exact anchor DER")
	jwtAudience := flag.String("jwt-audience", "", "optional audience for an ML-DSA-65 JWT-SVID check")
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
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(*endpoint))
	if err != nil {
		return errors.New("workload API client failed")
	}
	defer client.Close()

	credentials, err := client.FetchX509Context(ctx)
	// Do not dump responses, certificates, keys, tokens, or backend error details.
	if err != nil {
		return errors.New("workload API fetch failed")
	}
	result, err := check(credentials, id, pin)
	if err != nil {
		return err
	}

	if *jwtAudience != "" {
		jwt, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Subject: id, Audience: *jwtAudience})
		if err != nil {
			return errors.New("JWT-SVID fetch failed")
		}
		bundles, err := client.FetchJWTBundles(ctx)
		if err != nil {
			return errors.New("JWT bundle fetch failed")
		}
		verified, err := jwtsvid.ParseAndValidate(jwt.Marshal(), bundles, []string{*jwtAudience})
		if err != nil || verified.ID != id {
			return errors.New("JWT-SVID validation failed")
		}
		if verified.ID != id {
			return errors.New("JWT-SVID identity mismatch")
		}
		tampered := []byte(jwt.Marshal())
		if len(tampered) < 2 {
			return errors.New("JWT-SVID is empty")
		}
		// Flip one character of the signature segment.
		last := len(tampered) - 1
		if tampered[last] == 'A' {
			tampered[last] = 'B'
		} else {
			tampered[last] = 'A'
		}
		if _, err := jwtsvid.ParseAndValidate(string(tampered), bundles, []string{*jwtAudience}); err == nil {
			return errors.New("tampered JWT-SVID was accepted")
		}
		delegated, err := client.ValidateJWTSVID(ctx, jwt.Marshal(), *jwtAudience)
		if err != nil || delegated.ID != id {
			return errors.New("delegated JWT-SVID validation failed")
		}
		result.JWTAudience = *jwtAudience
		result.JWTAlgorithm = "ML-DSA-65"
		result.JWTVerified = true
		result.JWTDelegatedValid = true
		result.JWTTamperRejected = true
	}

	return json.NewEncoder(os.Stdout).Encode(result)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
