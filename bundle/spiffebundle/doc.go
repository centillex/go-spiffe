// Package spiffebundle provides SPIFFE bundle related functionality.
//
// A bundle represents a SPIFFE bundle, a collection of authorities for
// authenticating SVIDs. Under the qspiffe-pq-v1 profile only X.509 authorities
// are supported.
//
// You can create a new bundle for a specific trust domain:
//
//	td := spiffeid.RequireTrustDomainFromString("example.org")
//	bundle := spiffebundle.New(td)
//
// Or you can load it from disk:
//
//	td := spiffeid.RequireTrustDomainFromString("example.org")
//	bundle, err := spiffebundle.Load(td, "bundle.json")
//
// The bundle can be initialized with X.509 authorities:
//
//	td := spiffeid.RequireTrustDomainFromString("example.org")
//	var x509Authorities []*x509.Certificate = ...
//	bundle := spiffebundle.FromX509Authorities(td, x509Authorities)
//
// In addition, you can add X.509 authorities to the bundle:
//
//	var x509CA *x509.Certificate = ...
//	bundle.AddX509Authority(x509CA)
//
// Bundles can be organized into a set, keyed by trust domain:
//
//	set := spiffebundle.NewSet()
//	set.Add(bundle)
//
// A Source is a source of bundles for a trust domain. Both the Bundle and Set
// types implement Source:
//
//	// Initialize the source from a bundle or set
//	var source spiffebundle.Source = bundle
//	// ... or ...
//	var source spiffebundle.Source = set
//
//	// Use the source to query for X.509 bundles by trust domain
//	bundle, err := source.GetBundleForTrustDomain(td)
//
// The Bundle and Set types also implement the x509bundle.Source interface:
//
//	// As an x509bundle.Source...
//	var source x509bundle.Source = bundle // or set
//	x509Bundle, err := source.GetX509BundleForTrustDomain(td)
//
// JWT and WIT authorities are outside the strict profile. Their constructors
// discard authorities, mutators report pqprofile.ErrUnsupported, and the
// general bundle readers reject token entries. Use ParseX509Only or
// ReadX509Only when consuming bundles from peers that may also publish tokens.
package spiffebundle
