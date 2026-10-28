// Package pqjwk implements the public ML-DSA-65 certificate-entry subset of
// RFC 9964 and the SPIFFE X509-SVID bundle format. It does not handle private
// keys, tokens, trust-domain association, or authentic trust provisioning.
package pqjwk

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/spiffe/go-spiffe/v2/internal/pqpolicy"
)

type certificateEntry struct {
	KeyType      string   `json:"kty"`
	Algorithm    string   `json:"alg"`
	PublicKey    string   `json:"pub"`
	Use          string   `json:"use"`
	Certificates []string `json:"x5c"`
}

// MarshalX509Authority encodes signed DER, never caller-supplied parsed fields.
// It checks authority shape and algorithm admission, not authentic provisioning,
// certificate lifetime, or the necessity of trusting this authority.
func MarshalX509Authority(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, invalid("nil certificate")
	}
	canonical, err := parseAuthority(cert.Raw)
	if err != nil {
		return nil, err
	}
	key := canonical.PublicKey.(*mldsa.PublicKey)
	return json.Marshal(certificateEntry{KeyType: "AKP", Algorithm: "ML-DSA-65", PublicKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), Use: "x509-svid", Certificates: []string{base64.StdEncoding.EncodeToString(canonical.Raw)}})
}

// ParseX509Authority parses one recognized AKP x509-svid entry. Dispatching or
// ignoring unknown types/uses and absent/empty x5c is the bundle reader's job.
// Per X509-SVID section 6.2, only the first x5c certificate is used. Successful
// decoding is NOT authentication of the bundle or its claimed trust domain.
func ParseX509Authority(data []byte) (*x509.Certificate, error) {
	fields, err := object(data)
	if err != nil {
		return nil, err
	}
	for name, want := range map[string]string{"kty": "AKP", "alg": "ML-DSA-65", "use": "x509-svid"} {
		value, e := stringField(fields, name)
		if e != nil {
			return nil, e
		}
		if value != want {
			return nil, invalid("unsupported " + name)
		}
	}
	// No private material, kid, or competing key-type encodings are allowed in
	// this public X509-SVID entry. Optional unrelated extensions are not trusted.
	for _, name := range []string{"priv", "kid", "d", "p", "q", "dp", "dq", "qi", "oth", "k", "crv", "x", "y", "n", "e"} {
		if _, ok := fields[name]; ok {
			return nil, invalid("forbidden member " + name)
		}
	}
	encoded, err := stringField(fields, "pub")
	if err != nil {
		return nil, err
	}
	pub, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(pub) != encoded || len(pub) != mldsa.MLDSA65().PublicKeySize() {
		return nil, invalid("invalid ML-DSA-65 public key encoding")
	}
	var chain []string
	if err := json.Unmarshal(fields["x5c"], &chain); err != nil || len(chain) == 0 {
		return nil, invalid("x5c must contain a certificate")
	}
	der, err := base64.StdEncoding.Strict().DecodeString(chain[0])
	if err != nil || base64.StdEncoding.EncodeToString(der) != chain[0] {
		return nil, invalid("invalid x5c encoding")
	}
	cert, err := parseAuthority(der)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(pub, cert.PublicKey.(*mldsa.PublicKey).Bytes()) {
		return nil, invalid("public key does not match certificate")
	}
	if raw, ok := fields["key_ops"]; ok {
		var operations []string
		if err := json.Unmarshal(raw, &operations); err != nil || len(operations) != 1 || operations[0] != "verify" {
			return nil, invalid("key_ops must be verify")
		}
	}
	if _, ok := fields["x5t"]; ok {
		return nil, invalid("SHA-1 certificate thumbprints are unsupported")
	}
	if _, ok := fields["x5t#S256"]; ok {
		thumbprint, e := stringField(fields, "x5t#S256")
		if e != nil {
			return nil, e
		}
		hash := sha256.Sum256(cert.Raw)
		if thumbprint != base64.RawURLEncoding.EncodeToString(hash[:]) {
			return nil, invalid("certificate thumbprint mismatch")
		}
	}
	return cert, nil
}

func parseAuthority(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(bytes.Clone(der))
	if err != nil {
		return nil, invalid("invalid certificate DER")
	}
	if err := pqpolicy.CheckCertificate(cert); err != nil {
		return nil, err
	}
	if !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, invalid("authority must be a CA with keyCertSign")
	}
	return cert, nil
}

func stringField(fields map[string]json.RawMessage, name string) (string, error) {
	var value string
	raw, ok := fields[name]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", invalid("missing or null " + name)
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", invalid("invalid " + name)
	}
	return value, nil
}

// object rejects duplicate decoded member names, including escaped aliases,
// rather than accepting encoding/json's last-value-wins interpretation.
func object(data []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(data) {
		return nil, invalid("invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, invalid("expected JWK object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return nil, invalid("invalid object member")
		}
		name, ok := token.(string)
		if !ok {
			return nil, invalid("invalid object member")
		}
		if _, ok := fields[name]; ok {
			return nil, invalid("duplicate object member")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, invalid("invalid object value")
		}
		fields[name] = value
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return nil, invalid("unterminated object")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, invalid("trailing JSON data")
	}
	return fields, nil
}

func invalid(message string) error { return fmt.Errorf("%s: JWK: %s", pqpolicy.ID, message) }
