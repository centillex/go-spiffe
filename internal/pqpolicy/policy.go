// Package pqpolicy defines the immutable qspiffe-pq-v1 policy.
// It does not by itself enforce policy at SDK authentication boundaries.
package pqpolicy

import "crypto/tls"

const (
	ID = "qspiffe-pq-v1"
	// SecP256r1MLKEM768 is the approved native Go hybrid group.
	SecP256r1MLKEM768 tls.CurveID = tls.SecP256r1MLKEM768
)

// KeyExchangeGroups returns a fresh preference list so callers cannot mutate
// the shared policy. Other PQ groups are deliberately not approved.
func KeyExchangeGroups() []tls.CurveID {
	return []tls.CurveID{tls.X25519MLKEM768, SecP256r1MLKEM768}
}

func AllowsTLSVersion(version uint16) bool { return version == tls.VersionTLS13 }

func AllowsKeyExchange(group tls.CurveID) bool {
	return group == tls.X25519MLKEM768 || group == SecP256r1MLKEM768
}

// AllowsAuthenticationAlgorithm applies to certificate keys, certificate
// signatures, and TLS authentication. Callers must derive the canonical name
// from parsed cryptographic objects, never from untrusted claimed metadata.
func AllowsAuthenticationAlgorithm(name string) bool { return name == "ML-DSA-65" }

// AllowsIdentityFormat admits the implemented formats and rejects unknown ones.
func AllowsIdentityFormat(name string) bool {
	return name == "X509-SVID" || name == "JWT-SVID" || name == "WIT-SVID"
}

func AllowsResumption() bool { return false }
func AllowsEarlyData() bool  { return false }
