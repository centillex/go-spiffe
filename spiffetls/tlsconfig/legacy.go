package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// ErrUnsupportedAPI identifies legacy APIs that cannot enforce the strict
// profile. Use the owned Config returned by the configuration constructors.
var ErrUnsupportedAPI = errors.New("qspiffe-pq-v1: mutable TLS hooks and certificate-only authentication callbacks are unsupported; use an owned tlsconfig.Config")

func rejectLegacyHook(config *tls.Config) {
	if config == nil {
		return
	}
	resetAuthFields(config)
	config.VerifyPeerCertificate = nil
	config.VerifyConnection = func(tls.ConnectionState) error { return ErrUnsupportedAPI }
	config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, ErrUnsupportedAPI }
	config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, ErrUnsupportedAPI }
	config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return nil, ErrUnsupportedAPI }
}

// HookTLSClientConfig disables the legacy mutable-config integration.
//
// Deprecated: use TLSClientConfig and Config.Client or Config.DialContext.
func HookTLSClientConfig(config *tls.Config, _ x509bundle.Source, _ Authorizer, _ ...Option) {
	rejectLegacyHook(config)
}

// HookMTLSClientConfig disables the legacy mutable-config integration.
//
// Deprecated: use MTLSClientConfig and its owned connection methods.
func HookMTLSClientConfig(config *tls.Config, _ x509svid.Source, _ x509bundle.Source, _ Authorizer, _ ...Option) {
	rejectLegacyHook(config)
}

// HookMTLSWebClientConfig disables the legacy mutable-config integration.
//
// Deprecated: use MTLSWebClientConfig and its owned connection methods.
func HookMTLSWebClientConfig(config *tls.Config, _ x509svid.Source, _ *x509.CertPool, _ ...Option) {
	rejectLegacyHook(config)
}

// HookTLSServerConfig disables the legacy mutable-config integration.
//
// Deprecated: use TLSServerConfig and Config.Server or Config.Listener.
func HookTLSServerConfig(config *tls.Config, _ x509svid.Source, _ ...Option) {
	rejectLegacyHook(config)
}

// HookMTLSServerConfig disables the legacy mutable-config integration.
//
// Deprecated: use MTLSServerConfig and its owned connection methods.
func HookMTLSServerConfig(config *tls.Config, _ x509svid.Source, _ x509bundle.Source, _ Authorizer, _ ...Option) {
	rejectLegacyHook(config)
}

// HookMTLSWebServerConfig disables the legacy mutable-config integration.
//
// Deprecated: use MTLSWebServerConfig and its owned connection methods.
func HookMTLSWebServerConfig(config *tls.Config, _ *tls.Certificate, _ x509bundle.Source, _ Authorizer, _ ...Option) {
	rejectLegacyHook(config)
}

// VerifyPeerCertificate always returns ErrUnsupportedAPI. Certificate-only
// callbacks cannot enforce negotiated TLS policy and do not run on resumption.
//
// Deprecated: use an owned Config; use x509svid.Verify for certificate verification.
func VerifyPeerCertificate(_ x509bundle.Source, _ Authorizer, _ ...Option) func([][]byte, [][]*x509.Certificate) error {
	return func([][]byte, [][]*x509.Certificate) error { return ErrUnsupportedAPI }
}

// WrapVerifyPeerCertificate always returns ErrUnsupportedAPI without calling the
// supplied callback. It cannot establish strict-profile transport authentication.
//
// Deprecated: pass additional callbacks through WithBaseTLSConfig to an owned Config.
func WrapVerifyPeerCertificate(_ func([][]byte, [][]*x509.Certificate) error, _ x509bundle.Source, _ Authorizer, _ ...Option) func([][]byte, [][]*x509.Certificate) error {
	return func([][]byte, [][]*x509.Certificate) error { return ErrUnsupportedAPI }
}
