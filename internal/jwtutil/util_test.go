package jwtutil

import (
	"crypto"
	"crypto/mldsa"
	"testing"

	"github.com/stretchr/testify/require"
)

// Equality is a structural helper, not JWT validation or token trust admission.
func TestMLDSAAuthorityEquality(t *testing.T) {
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			key, err := mldsa.GenerateKey(params)
			require.NoError(t, err)
			pub := key.PublicKey()
			clone, err := mldsa.NewPublicKey(params, pub.Bytes())
			require.NoError(t, err)
			a := map[string]crypto.PublicKey{"key": pub}
			require.True(t, JWTAuthoritiesEqual(a, map[string]crypto.PublicKey{"key": clone}))
			require.True(t, JWTAuthoritiesEqual(a, CopyJWTAuthorities(a)))
			require.False(t, JWTAuthoritiesEqual(a, map[string]crypto.PublicKey{"other": pub}))
			require.False(t, JWTAuthoritiesEqual(a, nil))
			other, err := mldsa.GenerateKey(params)
			require.NoError(t, err)
			require.False(t, JWTAuthoritiesEqual(a, map[string]crypto.PublicKey{"key": other.Public()}))
		})
	}
	for _, key := range []crypto.PublicKey{nil, (*mldsa.PublicKey)(nil), &mldsa.PublicKey{}, "unsupported"} {
		authorities := map[string]crypto.PublicKey{"key": key}
		require.False(t, JWTAuthoritiesEqual(authorities, CopyJWTAuthorities(authorities)))
	}
}
