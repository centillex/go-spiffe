// Package pqjose implements the ML-DSA-65 subset of the JOSE serializations
// defined by RFC 9964: the AKP JWK key type, compact JWS signing and
// verification, and AKP JWK Sets.
//
// It intentionally supports one algorithm, ML-DSA-65, and rejects every other
// "alg" value, including "none" and the classical algorithms. Private AKP keys
// carry the 32-byte FIPS 204 seed in the "priv" member.
package pqjose

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	// KeyTypeAKP is the RFC 9964 JWK key type.
	KeyTypeAKP = "AKP"
	// Algorithm is the only JOSE algorithm admitted by this package.
	Algorithm = "ML-DSA-65"
)

var b64 = base64.RawURLEncoding.Strict()

// JWK is an RFC 9964 AKP JSON Web Key.
type JWK struct {
	KeyType   string `json:"kty"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid,omitempty"`
	Public    string `json:"pub"`
	Private   string `json:"priv,omitempty"`
	Use       string `json:"use,omitempty"`
}

// MarshalPublicJWK encodes a public key as an AKP JWK.
func MarshalPublicJWK(keyID string, publicKey *mldsa.PublicKey) ([]byte, error) {
	if keyID == "" {
		return nil, errors.New("pqjose: key ID is required")
	}
	if err := checkPublicKey(publicKey); err != nil {
		return nil, err
	}
	return json.Marshal(JWK{
		KeyType:   KeyTypeAKP,
		Algorithm: Algorithm,
		KeyID:     keyID,
		Public:    b64.EncodeToString(publicKey.Bytes()),
	})
}

// MarshalPublicJWKWithUse encodes a public key as an AKP JWK with the given
// JWK "use" value (for example "jwt-svid").
func MarshalPublicJWKWithUse(keyID, use string, publicKey *mldsa.PublicKey) ([]byte, error) {
	if keyID == "" {
		return nil, errors.New("pqjose: key ID is required")
	}
	if err := checkPublicKey(publicKey); err != nil {
		return nil, err
	}
	return json.Marshal(JWK{
		KeyType:   KeyTypeAKP,
		Algorithm: Algorithm,
		KeyID:     keyID,
		Public:    b64.EncodeToString(publicKey.Bytes()),
		Use:       use,
	})
}

// MarshalPrivateJWK encodes a private key as an AKP JWK carrying the seed.
func MarshalPrivateJWK(keyID string, privateKey *mldsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("pqjose: nil private key")
	}
	if privateKey.PublicKey().Parameters() != mldsa.MLDSA65() {
		return nil, fmt.Errorf("pqjose: unsupported private key parameters %q", privateKey.PublicKey().Parameters())
	}
	encoded, err := MarshalPublicJWK(keyID, privateKey.PublicKey())
	if err != nil {
		return nil, err
	}
	var jwk JWK
	if err := json.Unmarshal(encoded, &jwk); err != nil {
		return nil, err
	}
	jwk.Private = b64.EncodeToString(privateKey.Bytes())
	return json.Marshal(jwk)
}

// ParsePublicJWK parses a public AKP JWK. Public JWKS entries must not carry
// private material or metadata for another algorithm.
func ParsePublicJWK(data []byte) (string, *mldsa.PublicKey, error) {
	var jwk JWK
	if err := json.Unmarshal(data, &jwk); err != nil {
		return "", nil, fmt.Errorf("pqjose: malformed JWK: %w", err)
	}
	if jwk.KeyType != KeyTypeAKP {
		return "", nil, fmt.Errorf("pqjose: unsupported key type %q", jwk.KeyType)
	}
	if jwk.Algorithm != Algorithm {
		return "", nil, fmt.Errorf("pqjose: unsupported algorithm %q", jwk.Algorithm)
	}
	if jwk.Private != "" {
		return "", nil, errors.New("pqjose: public JWK contains private material")
	}
	if jwk.KeyID == "" {
		return "", nil, errors.New("pqjose: JWK is missing a key ID")
	}
	raw, err := b64.DecodeString(jwk.Public)
	if err != nil || b64.EncodeToString(raw) != jwk.Public {
		return "", nil, errors.New("pqjose: invalid public key encoding")
	}
	publicKey, err := mldsa.NewPublicKey(mldsa.MLDSA65(), raw)
	if err != nil {
		return "", nil, fmt.Errorf("pqjose: invalid ML-DSA-65 public key: %w", err)
	}
	return jwk.KeyID, publicKey, nil
}

// ParsePrivateJWK parses a private AKP JWK carrying a 32-byte seed.
func ParsePrivateJWK(data []byte) (string, *mldsa.PrivateKey, error) {
	var jwk JWK
	if err := json.Unmarshal(data, &jwk); err != nil {
		return "", nil, fmt.Errorf("pqjose: malformed JWK: %w", err)
	}
	if jwk.KeyType != KeyTypeAKP || jwk.Algorithm != Algorithm {
		return "", nil, errors.New("pqjose: only ML-DSA-65 AKP keys are supported")
	}
	if jwk.KeyID == "" {
		return "", nil, errors.New("pqjose: JWK is missing a key ID")
	}
	seed, err := b64.DecodeString(jwk.Private)
	if err != nil || b64.EncodeToString(seed) != jwk.Private || len(seed) != mldsa.PrivateKeySize {
		return "", nil, errors.New("pqjose: invalid private seed encoding")
	}
	privateKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		return "", nil, fmt.Errorf("pqjose: invalid ML-DSA-65 private key: %w", err)
	}
	if jwk.Public != "" {
		pub, err := b64.DecodeString(jwk.Public)
		if err != nil || !bytes.Equal(pub, privateKey.PublicKey().Bytes()) {
			return "", nil, errors.New("pqjose: public key does not match private seed")
		}
	}
	return jwk.KeyID, privateKey, nil
}

// Thumbprint computes the RFC 7638 JWK thumbprint for an AKP public key.
func Thumbprint(publicKey *mldsa.PublicKey) (string, error) {
	if err := checkPublicKey(publicKey); err != nil {
		return "", err
	}
	// RFC 9964 section 6 fixes the required members and their lexicographic
	// order to "alg", "kty", "pub".
	canonical := fmt.Sprintf(`{"alg":%q,"kty":%q,"pub":%q}`,
		Algorithm, KeyTypeAKP, b64.EncodeToString(publicKey.Bytes()))
	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:]), nil
}

func checkPublicKey(publicKey *mldsa.PublicKey) error {
	if publicKey == nil {
		return errors.New("pqjose: nil public key")
	}
	if publicKey.Parameters() != mldsa.MLDSA65() {
		return fmt.Errorf("pqjose: unsupported public key parameters %q", publicKey.Parameters())
	}
	raw := publicKey.Bytes()
	if len(raw) != mldsa.MLDSA65().PublicKeySize() {
		return errors.New("pqjose: invalid ML-DSA-65 public key size")
	}
	return nil
}

// Header is a parsed JWS protected header.
type Header struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid,omitempty"`
	Type      string `json:"typ,omitempty"`
}

// Token is a parsed compact JWS. The signature is not verified until Verify is
// called.
type Token struct {
	header  Header
	payload []byte
	input   []byte
	sig     []byte
}

// Header returns the parsed protected header.
func (t *Token) Header() Header { return t.header }

// Claims returns the raw payload.
func (t *Token) Claims() []byte { return bytes.Clone(t.payload) }

// SignJWT signs a compact JWS with the protected header alg=ML-DSA-65, the
// supplied key ID, and typ=JWT. The payload is used verbatim.
func SignJWT(keyID string, payload []byte, signer crypto.Signer) (string, error) {
	if keyID == "" {
		return "", errors.New("pqjose: key ID is required")
	}
	if signer == nil {
		return "", errors.New("pqjose: nil signer")
	}
	publicKey, ok := signer.Public().(*mldsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("pqjose: unsupported signer key type %T", signer.Public())
	}
	if err := checkPublicKey(publicKey); err != nil {
		return "", err
	}
	header := Header{Algorithm: Algorithm, KeyID: keyID, Type: "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(headerJSON) + "." + b64.EncodeToString(payload)
	signature, err := signer.Sign(nil, []byte(input), &mldsa.Options{})
	if err != nil {
		return "", fmt.Errorf("pqjose: sign: %w", err)
	}
	return input + "." + b64.EncodeToString(signature), nil
}

// ParseJWT parses a compact JWS and validates its protected header. It does not
// verify the signature.
func ParseJWT(token string) (*Token, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("pqjose: token must have three parts")
	}
	headerJSON, err := b64.DecodeString(parts[0])
	if err != nil || b64.EncodeToString(headerJSON) != parts[0] {
		return nil, errors.New("pqjose: invalid header encoding")
	}
	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("pqjose: invalid header: %w", err)
	}
	if header.Algorithm != Algorithm {
		return nil, fmt.Errorf("pqjose: unsupported algorithm %q", header.Algorithm)
	}
	if header.Type != "" && header.Type != "JWT" && header.Type != "JOSE" {
		return nil, fmt.Errorf("pqjose: unsupported token type %q", header.Type)
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil || b64.EncodeToString(payload) != parts[1] {
		return nil, errors.New("pqjose: invalid payload encoding")
	}
	signature, err := b64.DecodeString(parts[2])
	if err != nil || b64.EncodeToString(signature) != parts[2] {
		return nil, errors.New("pqjose: invalid signature encoding")
	}
	if len(signature) != mldsa.MLDSA65().SignatureSize() {
		return nil, errors.New("pqjose: invalid ML-DSA-65 signature size")
	}
	return &Token{
		header:  header,
		payload: payload,
		input:   []byte(parts[0] + "." + parts[1]),
		sig:     signature,
	}, nil
}

// Verify checks the signature with the given public key.
func (t *Token) Verify(publicKey *mldsa.PublicKey) error {
	if err := checkPublicKey(publicKey); err != nil {
		return err
	}
	if err := mldsa.Verify(publicKey, t.input, t.sig, &mldsa.Options{}); err != nil {
		return fmt.Errorf("pqjose: signature verification failed: %w", err)
	}
	return nil
}
