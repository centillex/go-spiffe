package x509svid

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/pqpolicy"
	"github.com/spiffe/go-spiffe/v2/internal/x509util"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// VerifyOption is an option used when verifying X509-SVIDs.
type VerifyOption interface {
	apply(config *verifyConfig)
}

// WithTime sets the time used when verifying validity periods on the X509-SVID.
// If not used, the current time will be used.
func WithTime(now time.Time) VerifyOption {
	return verifyOption(func(config *verifyConfig) {
		config.now = now
	})
}

// WithKeyUsage restricts verification to the peer's TLS role. Only ServerAuth
// and ClientAuth are supported. Without this option both usages are required.
func WithKeyUsage(usage x509.ExtKeyUsage) VerifyOption {
	return verifyOption(func(config *verifyConfig) { config.usage = usage; config.hasUsage = true })
}

// Verify verifies an X509-SVID chain using the X.509 bundle source. It
// returns the SPIFFE ID of the X509-SVID and one or more chains back to a root
// in the bundle. Only qspiffe-pq-v1 paths are returned. Signed DER is
// authoritative; mutations to parsed certificate fields are not trusted.
// Unless WithKeyUsage is specified, both TLS server and client usages are required.
func Verify(certs []*x509.Certificate, bundleSource x509bundle.Source, opts ...VerifyOption) (spiffeid.ID, [][]*x509.Certificate, error) {
	config := &verifyConfig{}
	for _, opt := range opts {
		opt.apply(config)
	}

	switch {
	case len(certs) == 0:
		return spiffeid.ID{}, nil, wrapX509svidErr(errors.New("empty certificates chain"))
	case bundleSource == nil:
		return spiffeid.ID{}, nil, wrapX509svidErr(errors.New("bundleSource is required"))
	}

	usages := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	if config.hasUsage {
		if config.usage != x509.ExtKeyUsageServerAuth && config.usage != x509.ExtKeyUsageClientAuth {
			return spiffeid.ID{}, nil, wrapX509svidErr(errors.New("unsupported verification key usage"))
		}
		usages = []x509.ExtKeyUsage{config.usage}
	}
	certs, err := pqpolicy.ParseCertificates(certs)
	if err != nil {
		return spiffeid.ID{}, nil, wrapX509svidErr(err)
	}
	leaf := certs[0]
	id, err := IDFromCert(leaf)
	if err != nil {
		return spiffeid.ID{}, nil, wrapX509svidErr(fmt.Errorf("could not get leaf SPIFFE ID: %w", err))
	}

	switch {
	case id.Path() == "":
		return id, nil, wrapX509svidErr(errors.New("leaf SPIFFE ID must have a non-root path"))
	case leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0:
		return id, nil, wrapX509svidErr(errors.New("leaf certificate requires digitalSignature key usage"))
	case leaf.IsCA:
		return id, nil, wrapX509svidErr(errors.New("leaf certificate with CA flag set to true"))
	case leaf.KeyUsage&x509.KeyUsageCertSign > 0:
		return id, nil, wrapX509svidErr(errors.New("leaf certificate with KeyCertSign key usage"))
	case leaf.KeyUsage&x509.KeyUsageCRLSign > 0:
		return id, nil, wrapX509svidErr(errors.New("leaf certificate with KeyCrlSign key usage"))
	}

	bundle, err := bundleSource.GetX509BundleForTrustDomain(id.TrustDomain())
	if err != nil {
		return id, nil, wrapX509svidErr(fmt.Errorf("could not get X509 bundle: %w", err))
	}

	if bundle == nil || bundle.TrustDomain() != id.TrustDomain() {
		return id, nil, wrapX509svidErr(errors.New("bundle is nil or has the wrong trust domain"))
	}
	authorities, err := pqpolicy.ParseCertificates(bundle.X509Authorities())
	if err != nil {
		return id, nil, wrapX509svidErr(err)
	}
	verifiedChains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         x509util.NewCertPool(authorities),
		Intermediates: x509util.NewCertPool(certs[1:]),
		KeyUsages:     usages,
		CurrentTime:   config.now,
	})
	if err != nil {
		return id, nil, wrapX509svidErr(fmt.Errorf("could not verify leaf certificate: %w", err))
	}

	approved := make([][]*x509.Certificate, 0, len(verifiedChains))
	for _, chain := range verifiedChains {
		if pqpolicy.CheckPath(chain, usages...) == nil {
			approved = append(approved, chain)
		}
	}
	if len(approved) == 0 {
		return id, nil, wrapX509svidErr(fmt.Errorf("%s: no approved certification path", pqpolicy.ID))
	}
	return id, approved, nil
}

// ParseAndVerify parses and verifies an X509-SVID chain using the X.509
// bundle source. It returns the SPIFFE ID of the X509-SVID and one or more
// chains back to a root in the bundle.
func ParseAndVerify(rawCerts [][]byte, bundleSource x509bundle.Source, opts ...VerifyOption) (spiffeid.ID, [][]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return spiffeid.ID{}, nil, wrapX509svidErr(fmt.Errorf("unable to parse certificate: %w", err))
		}
		certs = append(certs, cert)
	}
	return Verify(certs, bundleSource, opts...)
}

// IDFromCert extracts the SPIFFE ID from the URI SAN of the provided
// certificate. It will return an an error if the certificate does not have
// exactly one URI SAN with a well-formed SPIFFE ID.
func IDFromCert(cert *x509.Certificate) (spiffeid.ID, error) {
	switch {
	case cert == nil:
		return spiffeid.ID{}, errors.New("nil certificate")
	case len(cert.URIs) == 0:
		return spiffeid.ID{}, errors.New("certificate contains no URI SAN")
	case len(cert.URIs) > 1:
		return spiffeid.ID{}, errors.New("certificate contains more than one URI SAN")
	}
	if cert.URIs[0] == nil {
		return spiffeid.ID{}, errors.New("nil URI SAN")
	}
	return spiffeid.FromURI(cert.URIs[0])
}

type verifyConfig struct {
	now      time.Time
	usage    x509.ExtKeyUsage
	hasUsage bool
}

type verifyOption func(config *verifyConfig)

func (fn verifyOption) apply(config *verifyConfig) {
	fn(config)
}

func wrapX509svidErr(err error) error {
	return fmt.Errorf("x509svid: %w", err)
}
