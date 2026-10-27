package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMLDSAPublicKeyEquality(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	pub := key.PublicKey()
	clone, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pub.Bytes())
	require.NoError(t, err)
	equal, err := PublicKeyEqual(pub, clone)
	require.NoError(t, err)
	require.True(t, equal)
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		other, err := mldsa.GenerateKey(params)
		require.NoError(t, err)
		equal, err := PublicKeyEqual(pub, other.Public())
		require.NoError(t, err)
		require.False(t, equal)
	}
	for _, other := range []crypto.PublicKey{nil, (*mldsa.PublicKey)(nil), &mldsa.PublicKey{}, (*rsa.PublicKey)(nil), (*ecdsa.PublicKey)(nil), ed25519.PublicKey(nil), &rsa.PublicKey{}, &ecdsa.PublicKey{}, "unsupported"} {
		equal, _ := PublicKeyEqual(pub, other)
		require.False(t, equal)
		equal, _ = PublicKeyEqual(other, pub)
		require.False(t, equal)
		equal, _ = PublicKeyEqual(other, other)
		require.False(t, equal)
	}
}
