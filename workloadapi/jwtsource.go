package workloadapi

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

// JWTSource is a source of JWT-SVID and JWT bundles maintained via the
// Workload API.
//
// JWT-SVIDs are outside the qspiffe-pq-v1 profile. Constructing a JWTSource
// fails and every operation reports pqprofile.ErrUnsupported; the type remains
// so callers get a consistent, explicit error instead of a classical fallback.
type JWTSource struct{}

// NewJWTSource is unsupported under the strict profile.
func NewJWTSource(ctx context.Context, options ...JWTSourceOption) (_ *JWTSource, err error) {
	return nil, pqprofile.Unsupported("workloadapi.NewJWTSource")
}

// Close is a no-op; a source can never be constructed.
func (s *JWTSource) Close() error { return nil }

// FetchJWTSVID is unsupported under the strict profile.
func (s *JWTSource) FetchJWTSVID(ctx context.Context, params jwtsvid.Params) (*jwtsvid.SVID, error) {
	return nil, pqprofile.Unsupported("workloadapi.JWTSource.FetchJWTSVID")
}

// FetchJWTSVIDs is unsupported under the strict profile.
func (s *JWTSource) FetchJWTSVIDs(ctx context.Context, params jwtsvid.Params) ([]*jwtsvid.SVID, error) {
	return nil, pqprofile.Unsupported("workloadapi.JWTSource.FetchJWTSVIDs")
}

// GetJWTBundleForTrustDomain is unsupported under the strict profile.
func (s *JWTSource) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	return nil, pqprofile.Unsupported("workloadapi.JWTSource.GetJWTBundleForTrustDomain")
}

// WaitUntilUpdated is unsupported under the strict profile.
func (s *JWTSource) WaitUntilUpdated(ctx context.Context) error {
	return pqprofile.Unsupported("workloadapi.JWTSource.WaitUntilUpdated")
}

// Updated returns a closed channel; the source never updates.
func (s *JWTSource) Updated() <-chan struct{} {
	closed := make(chan struct{})
	close(closed)
	return closed
}
