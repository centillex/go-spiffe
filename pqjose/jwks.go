package pqjose

import (
	"crypto/mldsa"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

type jwkSet struct {
	Keys []json.RawMessage `json:"keys"`
}

// ParseJWKS parses a JWK Set containing only ML-DSA-65 AKP public keys.
func ParseJWKS(data []byte) (map[string]*mldsa.PublicKey, error) {
	var set jwkSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("pqjose: unable to parse JWKS: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("pqjose: JWKS contains no keys")
	}
	keys := make(map[string]*mldsa.PublicKey, len(set.Keys))
	for i, raw := range set.Keys {
		keyID, publicKey, err := ParsePublicJWK(raw)
		if err != nil {
			return nil, fmt.Errorf("pqjose: JWKS key %d: %w", i, err)
		}
		if keyID == "" {
			return nil, errors.New("pqjose: JWKS key is missing a key ID")
		}
		if _, ok := keys[keyID]; ok {
			return nil, fmt.Errorf("pqjose: duplicate key ID %q", keyID)
		}
		keys[keyID] = publicKey
	}
	return keys, nil
}

// MarshalJWKS encodes public keys as a deterministic JWK Set.
func MarshalJWKS(keys map[string]*mldsa.PublicKey) ([]byte, error) {
	return MarshalJWKSWithUse("", keys)
}

// MarshalJWKSWithUse encodes public keys with a JWK "use" value.
func MarshalJWKSWithUse(use string, keys map[string]*mldsa.PublicKey) ([]byte, error) {
	ids := make([]string, 0, len(keys))
	for keyID := range keys {
		ids = append(ids, keyID)
	}
	sort.Strings(ids)

	set := jwkSet{Keys: make([]json.RawMessage, 0, len(ids))}
	for _, keyID := range ids {
		encoded, err := MarshalPublicJWKWithUse(keyID, use, keys[keyID])
		if err != nil {
			return nil, err
		}
		set.Keys = append(set.Keys, encoded)
	}
	return json.Marshal(set)
}
