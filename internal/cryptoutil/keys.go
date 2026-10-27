package cryptoutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"fmt"
)

func PublicKeyEqual(a, b crypto.PublicKey) (bool, error) {
	switch a := a.(type) {
	case *mldsa.PublicKey:
		other, ok := b.(*mldsa.PublicKey)
		return ok && a != nil && other != nil && a.Equal(other), nil
	case *rsa.PublicKey:
		rsaPublicKey, ok := b.(*rsa.PublicKey)
		return ok && RSAPublicKeyEqual(a, rsaPublicKey), nil
	case *ecdsa.PublicKey:
		ecdsaPublicKey, ok := b.(*ecdsa.PublicKey)
		return ok && ECDSAPublicKeyEqual(a, ecdsaPublicKey), nil
	case ed25519.PublicKey:
		ed25519PublicKey, ok := b.(ed25519.PublicKey)
		return ok && len(a) == ed25519.PublicKeySize && len(ed25519PublicKey) == ed25519.PublicKeySize && bytes.Equal(a, ed25519PublicKey), nil
	default:
		return false, fmt.Errorf("unsupported public key type %T", a)
	}
}

func RSAPublicKeyEqual(a, b *rsa.PublicKey) bool {
	return a != nil && b != nil && a.N != nil && b.N != nil && a.E == b.E && a.N.Cmp(b.N) == 0
}

func ECDSAPublicKeyEqual(a, b *ecdsa.PublicKey) bool {
	if a == nil || b == nil || a.Curve == nil || a.Curve != b.Curve {
		return false
	}
	aBytes, aErr := a.Bytes()
	bBytes, bErr := b.Bytes()
	return aErr == nil && bErr == nil && bytes.Equal(aBytes, bBytes)
}
