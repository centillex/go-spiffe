// Package compat provides the upstream go-spiffe tlsconfig surface for callers
// that still expect raw *tls.Config values.
//
// The constructors delegate to the owned tlsconfig package and return a clone
// of its policy-bearing *tls.Config. The clone enforces the strict profile at
// handshake time, but callers can mutate it or replace its callbacks afterward;
// those mutations are outside the owned API's guarantees. New code should use
// the owned API instead.
package compat

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"reflect"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// Authorizer is the upstream authorizer type.
type Authorizer = tlsconfig.Authorizer

// Option, Trace and certificate-info types are shared with the owned API.
type (
	Option             = tlsconfig.Option
	Trace              = tlsconfig.Trace
	GetCertificateInfo = tlsconfig.GetCertificateInfo
	GotCertificateInfo = tlsconfig.GotCertificateInfo
)

// WithTrace forwards to the owned option.
func WithTrace(trace Trace) Option { return tlsconfig.WithTrace(trace) }

// Authorizer constructors forwarded for source compatibility.
func AdaptMatcher(matcher spiffeid.Matcher) Authorizer { return tlsconfig.AdaptMatcher(matcher) }
func AuthorizeAny() Authorizer                         { return tlsconfig.AuthorizeAny() }
func AuthorizeID(allowed spiffeid.ID) Authorizer       { return tlsconfig.AuthorizeID(allowed) }
func AuthorizeIDPrefix(allowed spiffeid.ID) Authorizer {
	return tlsconfig.AuthorizeIDPrefix(allowed)
}
func AuthorizeMemberOf(allowed spiffeid.TrustDomain) Authorizer {
	return tlsconfig.AuthorizeMemberOf(allowed)
}
func AuthorizeOneOf(allowed ...spiffeid.ID) Authorizer { return tlsconfig.AuthorizeOneOf(allowed...) }

// GetCertificate and GetClientCertificate match the upstream callbacks.
func GetCertificate(svid x509svid.Source, opts ...Option) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return tlsconfig.GetCertificate(svid, opts...)
}

func GetClientCertificate(svid x509svid.Source, opts ...Option) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return tlsconfig.GetClientCertificate(svid, opts...)
}

// TLSClientConfig authenticates and authorizes a server SVID.
func TLSClientConfig(bundle x509bundle.Source, authorizer Authorizer, opts ...Option) *tls.Config {
	return tlsconfig.TLSClientConfig(bundle, authorizer, opts...).CompatibilityTLSConfig()
}

// MTLSClientConfig requires mutual SVID authentication.
func MTLSClientConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) *tls.Config {
	return tlsconfig.MTLSClientConfig(svid, bundle, authorizer, opts...).CompatibilityTLSConfig()
}

// TLSServerConfig presents a server SVID without client authentication.
func TLSServerConfig(svid x509svid.Source, opts ...Option) *tls.Config {
	return tlsconfig.TLSServerConfig(svid, opts...).CompatibilityTLSConfig()
}

// MTLSServerConfig requires and authorizes a client SVID.
func MTLSServerConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) *tls.Config {
	return tlsconfig.MTLSServerConfig(svid, bundle, authorizer, opts...).CompatibilityTLSConfig()
}

// MTLSWebClientConfig requires mutual TLS with a PQ Web PKI server.
func MTLSWebClientConfig(svid x509svid.Source, roots *x509.CertPool, opts ...Option) *tls.Config {
	return tlsconfig.MTLSWebClientConfig(svid, roots, opts...).CompatibilityTLSConfig()
}

// MTLSWebServerConfig presents a PQ Web PKI credential and authorizes clients.
func MTLSWebServerConfig(cert *tls.Certificate, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) *tls.Config {
	return tlsconfig.MTLSWebServerConfig(cert, bundle, authorizer, opts...).CompatibilityTLSConfig()
}

// WebClientConfig authenticates a PQ Web PKI server.
func WebClientConfig(roots *x509.CertPool, opts ...Option) *tls.Config {
	return tlsconfig.WebClientConfig(roots, opts...).CompatibilityTLSConfig()
}

// WebServerConfig presents a PQ Web PKI credential.
func WebServerConfig(cert *tls.Certificate, opts ...Option) *tls.Config {
	return tlsconfig.WebServerConfig(cert, opts...).CompatibilityTLSConfig()
}

// HookTLSClientConfig installs client policy into an existing config.
func HookTLSClientConfig(config *tls.Config, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) {
	install(config, tlsconfig.TLSClientConfig(bundle, authorizer, append(opts, tlsconfig.WithBaseTLSConfig(config))...))
}

// HookMTLSClientConfig installs mutual client policy into an existing config.
func HookMTLSClientConfig(config *tls.Config, svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) {
	install(config, tlsconfig.MTLSClientConfig(svid, bundle, authorizer, append(opts, tlsconfig.WithBaseTLSConfig(config))...))
}

// HookTLSServerConfig installs server policy into an existing config.
func HookTLSServerConfig(config *tls.Config, svid x509svid.Source, opts ...Option) {
	install(config, tlsconfig.TLSServerConfig(svid, append(opts, tlsconfig.WithBaseTLSConfig(config))...))
}

// HookMTLSServerConfig installs mutual server policy into an existing config.
func HookMTLSServerConfig(config *tls.Config, svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) {
	install(config, tlsconfig.MTLSServerConfig(svid, bundle, authorizer, append(opts, tlsconfig.WithBaseTLSConfig(config))...))
}

// HookMTLSWebClientConfig installs PQ Web PKI client policy.
func HookMTLSWebClientConfig(config *tls.Config, svid x509svid.Source, roots *x509.CertPool, opts ...Option) {
	install(config, tlsconfig.MTLSWebClientConfig(svid, roots, append(opts, tlsconfig.WithBaseTLSConfig(config))...))
}

// HookMTLSWebServerConfig installs PQ Web PKI server policy.
func HookMTLSWebServerConfig(config *tls.Config, cert *tls.Certificate, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) {
	install(config, tlsconfig.MTLSWebServerConfig(cert, bundle, authorizer, append(opts, tlsconfig.WithBaseTLSConfig(config))...))
}

func install(config *tls.Config, owned *tlsconfig.Config) {
	if config == nil {
		return
	}
	clone := owned.CompatibilityTLSConfig()
	if clone == nil {
		return
	}
	// Copy exported fields individually so the caller's unexported lock state is
	// preserved. The hook is expected to run before the config is used.
	dst := reflect.ValueOf(config).Elem()
	src := reflect.ValueOf(clone).Elem()
	for i := 0; i < src.NumField(); i++ {
		if src.Type().Field(i).PkgPath != "" {
			continue
		}
		dst.Field(i).Set(src.Field(i))
	}
}

// VerifyPeerCertificate returns an upstream-shaped verification callback that
// applies the strict SPIFFE path checks and the supplied authorizer.
func VerifyPeerCertificate(bundle x509bundle.Source, authorizer Authorizer, _ ...Option) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if authorizer == nil {
			return errors.New("authorizer is required")
		}
		id, chains, err := x509svid.ParseAndVerify(rawCerts, bundle)
		if err != nil {
			return err
		}
		return authorizer(id, chains)
	}
}

// WrapVerifyPeerCertificate wraps an existing callback with SPIFFE
// verification, passing the verified chains to the wrapped callback.
func WrapVerifyPeerCertificate(wrapped func([][]byte, [][]*x509.Certificate) error, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) func([][]byte, [][]*x509.Certificate) error {
	if wrapped == nil {
		return VerifyPeerCertificate(bundle, authorizer, opts...)
	}
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if authorizer == nil {
			return errors.New("authorizer is required")
		}
		id, chains, err := x509svid.ParseAndVerify(rawCerts, bundle)
		if err != nil {
			return err
		}
		if err := authorizer(id, chains); err != nil {
			return err
		}
		return wrapped(rawCerts, chains)
	}
}
