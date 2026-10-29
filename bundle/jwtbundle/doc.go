// Package jwtbundle provides JWT bundle types.
//
// JWT authorities are ML-DSA-65 AKP public keys (RFC 9964). Parsing rejects
// classical algorithms and malformed/private entries so the strict
// post-quantum profile has no classical token fallback.
package jwtbundle
