package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func newTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
}

// Native configurations are test-only controls for low-level hook/handshake
// regression tests. Production constructors only return owned Config values.
func nativeTLSClientConfig(bundle x509bundle.Source, authorizer Authorizer) *tls.Config {
	config := newTLSConfig()
	hookTLSClientConfig(config, bundle, authorizer)
	return config
}

func nativeMTLSClientConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) *tls.Config {
	config := newTLSConfig()
	hookMTLSClientConfig(config, svid, bundle, authorizer, opts...)
	return config
}

func nativeMTLSWebClientConfig(svid x509svid.Source, roots *x509.CertPool, opts ...Option) *tls.Config {
	config := newTLSConfig()
	hookMTLSWebClientConfig(config, svid, roots, opts...)
	return config
}

func nativeTLSServerConfig(svid x509svid.Source, opts ...Option) *tls.Config {
	config := newTLSConfig()
	hookTLSServerConfig(config, svid, opts...)
	return config
}

func nativeMTLSServerConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer, opts ...Option) *tls.Config {
	config := newTLSConfig()
	hookMTLSServerConfig(config, svid, bundle, authorizer, opts...)
	return config
}

func nativeMTLSWebServerConfig(cert *tls.Certificate, bundle x509bundle.Source, authorizer Authorizer) *tls.Config {
	config := newTLSConfig()
	hookMTLSWebServerConfig(config, cert, bundle, authorizer)
	return config
}

func verifyPeerCertificate(bundle x509bundle.Source, authorizer Authorizer) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		id, certs, err := x509svid.ParseAndVerify(raw, bundle)
		if err != nil {
			return err
		}

		if authorizer == nil {
			return profileError("authorizer is required")
		}
		return authorizer(id, certs)
	}
}

func wrapVerifyPeerCertificate(wrapped func([][]byte, [][]*x509.Certificate) error, bundle x509bundle.Source, authorizer Authorizer) func([][]byte, [][]*x509.Certificate) error {
	if wrapped == nil {
		return verifyPeerCertificate(bundle, authorizer)
	}

	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		id, certs, err := x509svid.ParseAndVerify(raw, bundle)
		if err != nil {
			return err
		}

		if authorizer == nil {
			return profileError("authorizer is required")
		}
		if err := authorizer(id, certs); err != nil {
			return err
		}

		return wrapped(raw, certs)
	}
}
