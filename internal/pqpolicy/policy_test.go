package pqpolicy

import (
	"crypto/tls"
	"testing"
)

func TestTLSAllowLists(t *testing.T) {
	// Exhaust the wire identifier space: unknown/future identifiers must fail
	// closed rather than inherit permission from a broad PQ classification.
	for n := 0; n <= 65535; n++ {
		v := uint16(n)
		if got := AllowsTLSVersion(v); got != (v == tls.VersionTLS13) {
			t.Fatalf("TLS version %d: allowed=%v", v, got)
		}
		want := n == 4588 || n == 4587
		if got := AllowsKeyExchange(tls.CurveID(v)); got != want {
			t.Fatalf("group %d: allowed=%v, want %v", n, got, want)
		}
	}
}

func TestPreferencesCannotMutatePolicy(t *testing.T) {
	groups := KeyExchangeGroups()
	if len(groups) != 2 || groups[0] != tls.CurveID(4588) || groups[1] != tls.CurveID(4587) {
		t.Fatalf("unexpected preferences: %v", groups)
	}
	groups[0] = tls.X25519
	if KeyExchangeGroups()[0] != tls.CurveID(4588) || AllowsKeyExchange(tls.X25519) {
		t.Fatal("caller mutation weakened policy")
	}
}

func TestAuthenticationAlgorithms(t *testing.T) {
	if !AllowsAuthenticationAlgorithm("ML-DSA-65") {
		t.Fatal("required algorithm rejected")
	}
	for _, name := range []string{"", "RSA", "ECDSA", "Ed25519", "ML-DSA-44", "ML-DSA-87", "ml-dsa-65", "ML-DSA-65 ", "unknown"} {
		if AllowsAuthenticationAlgorithm(name) {
			t.Errorf("unexpected algorithm allowed: %q", name)
		}
	}
}

func TestIdentityFormats(t *testing.T) {
	if !AllowsIdentityFormat("X509-SVID") {
		t.Fatal("required format rejected")
	}
	if !AllowsIdentityFormat("JWT-SVID") {
		t.Fatal("JWT-SVID must be admitted")
	}
	for _, name := range []string{"", "WIT", "unknown", "x509-svid"} {
		if AllowsIdentityFormat(name) {
			t.Errorf("unexpected identity format allowed: %q", name)
		}
	}
}

func TestNoSessionFallback(t *testing.T) {
	if ID != "qspiffe-pq-v1" || AllowsResumption() || AllowsEarlyData() {
		t.Fatal("unexpected profile or session policy")
	}
}
