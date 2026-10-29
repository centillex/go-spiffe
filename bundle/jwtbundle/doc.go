// Package jwtbundle provides JWT bundle types.
//
// JWT-SVIDs and JWT trust are outside the qspiffe-pq-v1 profile implemented by
// this SDK. The package remains for source compatibility, but no authority can
// be admitted: parsers, loaders, marshaling and trust-domain lookups report
// pqprofile.ErrUnsupported, and constructors always yield empty bundles.
//
// Callers should detect pqprofile.ErrUnsupported with errors.Is and use X.509
// bundles instead.
package jwtbundle
