package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/pqpolicy"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// HookTLSClientConfig sets up the TLS configuration to verify and authorize
// the server X509-SVID. If there is an existing callback set for
// VerifyPeerCertificate it will be wrapped by this package and invoked
// after SPIFFE authentication has completed.
func hookTLSClientConfig(config *tls.Config, bundle x509bundle.Source, authorizer Authorizer) {
	resetAuthFields(config)
	config.InsecureSkipVerify = true // SPIFFE authentication is enforced by VerifyConnection.
	installConnectionPolicy(config, bundle, authorizer, x509.ExtKeyUsageServerAuth, false, false, false)
}

// A Option changes the defaults used to by mTLS ClientConfig functions.
type Option interface {
	apply(*options)
}

type option func(*options)

func (fn option) apply(o *options) { fn(o) }

type options struct {
	trace Trace
	base  *tls.Config
}

func newOptions(opts []Option) *options {
	out := &options{}
	for _, opt := range opts {
		opt.apply(out)
	}
	return out
}

// WithTrace will use the provided tracing callbacks
// when various TLS config functions gets invoked.
func WithTrace(trace Trace) Option {
	return option(func(opts *options) {
		opts.trace = trace
	})
}

// HookMTLSClientConfig sets up the TLS configuration to present an X509-SVID
// to the server and verify and authorize the server X509-SVID. If there is an
// existing callback set for VerifyPeerCertificate it will be wrapped by
// this package and invoked after SPIFFE authentication has completed.
func hookMTLSClientConfig(config *tls.Config, svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) {
	resetAuthFields(config)
	config.GetClientCertificate = GetClientCertificate(svid, opts...)
	config.InsecureSkipVerify = true // SPIFFE authentication is enforced by VerifyConnection.
	installConnectionPolicy(config, bundle, authorizer, x509.ExtKeyUsageServerAuth, true, false, false)
}

// HookMTLSWebClientConfig sets up the TLS configuration to present an
// X509-SVID to the server and verifies the server certificate using the
// provided roots (or the system roots if nil).
func hookMTLSWebClientConfig(config *tls.Config, svid x509svid.Source, roots *x509.CertPool, opts ...Option) {
	resetAuthFields(config)
	config.GetClientCertificate = GetClientCertificate(svid, opts...)
	config.RootCAs = roots
	installConnectionPolicy(config, nil, nil, x509.ExtKeyUsageServerAuth, true, true, false)
}

// HookTLSServerConfig sets up the TLS configuration to present an X509-SVID
// to the client and to not require or verify client certificates.
func hookTLSServerConfig(config *tls.Config, svid x509svid.Source, opts ...Option) {
	resetAuthFields(config)
	config.GetCertificate = GetCertificate(svid, opts...)
	installConnectionPolicy(config, nil, nil, x509.ExtKeyUsageClientAuth, true, false, true)
}

// HookMTLSServerConfig sets up the TLS configuration to present an X509-SVID
// to the client and require, verify, and authorize the client X509-SVID. If
// there is an existing callback set for VerifyPeerCertificate it will be
// wrapped by this package and invoked after SPIFFE authentication has
// completed.
func hookMTLSServerConfig(config *tls.Config, svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) {
	resetAuthFields(config)
	config.ClientAuth = tls.RequireAnyClientCert
	config.GetCertificate = GetCertificate(svid, opts...)
	installConnectionPolicy(config, bundle, authorizer, x509.ExtKeyUsageClientAuth, true, false, false)
}

// HookMTLSWebServerConfig sets up the TLS configuration to presents a web
// server certificate to the client and require, verify, and authorize client
// X509-SVIDs. If there is an existing callback set for VerifyPeerCertificate
// it will be wrapped by this package and invoked after SPIFFE
// authentication has completed.
func hookMTLSWebServerConfig(config *tls.Config, cert *tls.Certificate, bundle x509bundle.Source, authorizer Authorizer) {
	resetAuthFields(config)
	config.ClientAuth = tls.RequireAnyClientCert
	config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if cert == nil {
			return nil, profileError("nil Web PKI credential")
		}
		copy := *cert
		if err := validateLocalKey(&copy); err != nil {
			return nil, err
		}
		return &copy, nil
	}
	installConnectionPolicy(config, bundle, authorizer, x509.ExtKeyUsageClientAuth, true, false, false)
}

// GetCertificate returns a GetCertificate callback for tls.Config. It uses the
// given X509-SVID getter to obtain a server X509-SVID for the TLS handshake.
func GetCertificate(svid x509svid.Source, opts ...Option) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	opt := newOptions(opts)
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := getTLSCertificate(svid, opt.trace)
		if err != nil {
			return nil, err
		}
		_, err = checkPresentedChain(cert.Certificate, x509.ExtKeyUsageServerAuth)
		return cert, err
	}
}

// GetClientCertificate returns a GetClientCertificate callback for tls.Config.
// It uses the given X509-SVID getter to obtain a client X509-SVID for the TLS
// handshake.
func GetClientCertificate(svid x509svid.Source, opts ...Option) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	opt := newOptions(opts)
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		cert, err := getTLSCertificate(svid, opt.trace)
		if err != nil {
			return nil, err
		}
		_, err = checkPresentedChain(cert.Certificate, x509.ExtKeyUsageClientAuth)
		return cert, err
	}
}

func getTLSCertificate(svid x509svid.Source, trace Trace) (*tls.Certificate, error) {
	var traceVal any
	if trace.GetCertificate != nil {
		traceVal = trace.GetCertificate(GetCertificateInfo{})
	}

	if svid == nil {
		return nil, profileError("SVID source is required")
	}
	s, err := svid.GetX509SVID()
	if err != nil {
		if trace.GotCertificate != nil {
			trace.GotCertificate(GotCertificateInfo{Err: err}, traceVal)
		}
		return nil, err
	}

	if s == nil || len(s.Certificates) == 0 {
		return nil, profileError("empty SVID")
	}
	cert := &tls.Certificate{
		Certificate: make([][]byte, 0, len(s.Certificates)),
		PrivateKey:  s.PrivateKey,
		Leaf:        s.Certificates[0],
	}

	for _, svidCert := range s.Certificates {
		if svidCert == nil {
			return nil, profileError("nil SVID certificate")
		}
		cert.Certificate = append(cert.Certificate, append([]byte(nil), svidCert.Raw...))
	}

	if err := validateLocalKey(cert); err != nil {
		return nil, err
	}
	id, err := x509svid.IDFromCert(cert.Leaf)
	if err != nil || id != s.ID || id.Path() == "" {
		return nil, profileError("local SVID identity mismatch")
	}
	if trace.GotCertificate != nil {
		// Tracing is observational: do not expose signing material or mutable
		// handshake certificate slices to the callback.
		observed := snapshotCertificate(*cert)
		observed.PrivateKey = nil
		observed.Leaf, _ = x509.ParseCertificate(observed.Certificate[0])
		trace.GotCertificate(GotCertificateInfo{Cert: &observed}, traceVal)
	}

	return cert, nil
}

func resetAuthFields(config *tls.Config) {
	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13
	config.CurvePreferences = pqpolicy.KeyExchangeGroups()
	config.SessionTicketsDisabled = true
	config.ClientSessionCache = nil
	config.WrapSession = nil
	config.UnwrapSession = nil
	config.Rand = nil //nolint:staticcheck // never use caller-selected production randomness
	if config.GetConfigForClient != nil {
		config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return nil, profileError("GetConfigForClient overrides are unsupported")
		}
	}
	config.Certificates = nil
	config.ClientAuth = tls.NoClientCert
	config.GetCertificate = nil
	config.GetClientCertificate = nil
	config.InsecureSkipVerify = false
	config.NameToCertificate = nil //nolint:staticcheck // setting to nil is OK
	config.RootCAs = nil
}
