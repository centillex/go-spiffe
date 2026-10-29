// Package witbundle provides WIT bundle types.
//
// WIT-SVIDs and WIT trust are outside the qspiffe-pq-v1 profile implemented by
// this SDK. The package remains for source compatibility, but no authority can
// be admitted: parsers, loaders, marshaling and trust-domain lookups report
// pqprofile.ErrUnsupported, and constructors always yield empty bundles.
package witbundle
