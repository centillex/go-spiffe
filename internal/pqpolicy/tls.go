package pqpolicy

import (
	"crypto/tls"
	"fmt"
)

// CheckTLS checks negotiated protocol policy, not certificate authentication.
func CheckTLS(state tls.ConnectionState) error {
	if !AllowsTLSVersion(state.Version) {
		return fmt.Errorf("%s: TLS 1.3 is required", ID)
	}
	if !AllowsKeyExchange(state.CurveID) {
		return fmt.Errorf("%s: unapproved key exchange group", ID)
	}
	if state.DidResume {
		return fmt.Errorf("%s: session resumption is disabled", ID)
	}
	return nil
}

// CheckMutualTLS is a post-handshake guard for SDK-owned connections. On a TLS
// client VerifyConnection runs before the client certificate is selected/sent,
// so it cannot establish that the server actually requested client credentials.
// This complements, but does not replace, certificate/path authorization.
func CheckMutualTLS(state tls.ConnectionState) error {
	if err := CheckTLS(state); err != nil {
		return err
	}
	if !state.HandshakeComplete || len(state.LocalCertificate) == 0 || len(state.PeerCertificates) == 0 {
		return fmt.Errorf("%s: completed mutual certificate exchange is required", ID)
	}
	return nil
}
