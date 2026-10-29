package workloadapi

import (
	"context"

	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// WITSource is a source of WIT-SVIDs and WIT bundles maintained via the
// Workload API. It implements both witsvid.Source and witbundle.Source.
//
// WIT is outside the qspiffe-pq-v1 profile. Constructing a WITSource fails and
// every operation reports pqprofile.ErrUnsupported; the type remains so callers
// get a consistent, explicit error instead of a classical fallback.
//
// Experimental: subject to change.
type WITSource struct{}

// NewWITSource is unsupported under the strict profile.
//
// Experimental: subject to change.
func NewWITSource(ctx context.Context, options ...WITSourceOption) (_ *WITSource, err error) {
	return nil, pqprofile.Unsupported("workloadapi.NewWITSource")
}

// Close is a no-op; a source can never be constructed.
//
// Experimental: subject to change.
func (s *WITSource) Close() error { return nil }

// GetWITSVIDForID is unsupported under the strict profile.
//
// Experimental: subject to change.
func (s *WITSource) GetWITSVIDForID(id spiffeid.ID) (*witsvid.SVID, error) {
	return nil, pqprofile.Unsupported("workloadapi.WITSource.GetWITSVIDForID")
}

// GetWITBundleForTrustDomain is unsupported under the strict profile.
//
// Experimental: subject to change.
func (s *WITSource) GetWITBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*witbundle.Bundle, error) {
	return nil, pqprofile.Unsupported("workloadapi.WITSource.GetWITBundleForTrustDomain")
}

// WaitUntilUpdated is unsupported under the strict profile.
//
// Experimental: subject to change.
func (s *WITSource) WaitUntilUpdated(ctx context.Context) error {
	return pqprofile.Unsupported("workloadapi.WITSource.WaitUntilUpdated")
}

// Updated returns a closed channel; the source never updates.
//
// Experimental: subject to change.
func (s *WITSource) Updated() <-chan struct{} {
	closed := make(chan struct{})
	close(closed)
	return closed
}

// OnWITSVIDsUpdate implements WITSVIDWatcher. Updates cannot carry trust.
func (s *WITSource) OnWITSVIDsUpdate(svids []*witsvid.SVID) {}

// OnWITSVIDsWatchError implements WITSVIDWatcher.
func (s *WITSource) OnWITSVIDsWatchError(error) {}

// OnWITBundlesUpdate implements WITBundleWatcher. Updates cannot carry trust.
func (s *WITSource) OnWITBundlesUpdate(bundles *witbundle.Set) {}

// OnWITBundlesWatchError implements WITBundleWatcher.
func (s *WITSource) OnWITBundlesWatchError(error) {}
