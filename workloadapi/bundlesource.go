package workloadapi

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// BundleSource is a source of SPIFFE bundles maintained via the Workload API.
//
// Updates are validated and applied atomically. A malformed, profile-violating,
// empty, or expired update, or a Workload API watch error, makes the source
// unready: lookups then fail instead of serving stale trust. The next valid
// update makes it ready again.
type BundleSource struct {
	watcher *watcher
	now     func() time.Time

	mtx             sync.RWMutex
	x509Authorities map[spiffeid.TrustDomain][]*x509.Certificate
	life            sourceLifecycle

	closeMtx sync.RWMutex
	closed   bool
}

// NewBundleSource creates a new BundleSource. It blocks until the initial
// update has been received from the Workload API. The source should be closed
// when no longer in use to free underlying resources.
func NewBundleSource(ctx context.Context, options ...BundleSourceOption) (_ *BundleSource, err error) {
	config := &bundleSourceConfig{}
	for _, option := range options {
		option.configureBundleSource(config)
	}

	s := &BundleSource{
		now:             time.Now,
		x509Authorities: make(map[spiffeid.TrustDomain][]*x509.Certificate),
	}

	// JWT bundle watching is deliberately not started: token trust is outside
	// the strict profile and must not be merged into X.509 bundles.
	s.watcher, err = newWatcher(ctx, config.watcher, s.setX509Context, s.setX509ContextError, nil)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Close closes the source, dropping the connection to the Workload API.
// Other source methods will return an error after Close has been called.
// The underlying Workload API client will also be closed if it is owned by
// the BundleSource (i.e. not provided via the WithClient option).
func (s *BundleSource) Close() error {
	s.closeMtx.Lock()
	s.closed = true
	s.closeMtx.Unlock()

	return s.watcher.Close()
}

// Ready returns nil when the source holds a currently valid, profile-compliant
// bundle set and ErrSourceUnready (possibly wrapped with a reason) otherwise.
func (s *BundleSource) Ready() error {
	if err := s.checkClosed(); err != nil {
		return err
	}
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	if err := s.readyLocked(); err != nil {
		return wrapBundlesourceErr(err)
	}
	return nil
}

// State returns an immutable snapshot of the source lifecycle state.
func (s *BundleSource) State() SourceState {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	state := s.life.state()
	if state.Ready {
		if err := s.validateLocked(); err != nil {
			state.Ready = false
			state.Reason = err.Error()
		}
	}
	return state
}

// Snapshot returns an atomically consistent copy of the current bundle set and
// lifecycle state.
func (s *BundleSource) Snapshot() (*x509bundle.Set, SourceState, error) {
	if err := s.checkClosed(); err != nil {
		return nil, SourceState{}, err
	}
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	state := s.life.state()
	if err := s.readyLocked(); err != nil {
		state.Ready = false
		state.Reason = err.Error()
		return nil, state, wrapBundlesourceErr(err)
	}
	set := x509bundle.NewSet()
	for trustDomain, authorities := range s.x509Authorities {
		set.Add(x509bundle.FromX509Authorities(trustDomain, authorities))
	}
	return set, state, nil
}

// GetBundleForTrustDomain returns the SPIFFE bundle for the given trust
// domain. It implements the spiffebundle.Source interface.
func (s *BundleSource) GetBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*spiffebundle.Bundle, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	if err := s.readyLocked(); err != nil {
		return nil, wrapBundlesourceErr(err)
	}
	x509Authorities, ok := s.x509Authorities[trustDomain]
	if !ok {
		return nil, wrapBundlesourceErr(fmt.Errorf("no SPIFFE bundle for trust domain %q", trustDomain))
	}
	bundle := spiffebundle.New(trustDomain)
	bundle.SetX509Authorities(x509Authorities)
	return bundle, nil
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain. It implements the x509bundle.Source interface.
func (s *BundleSource) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	if err := s.readyLocked(); err != nil {
		return nil, wrapBundlesourceErr(err)
	}
	x509Authorities, hasX509Authorities := s.x509Authorities[trustDomain]
	if !hasX509Authorities {
		return nil, wrapBundlesourceErr(fmt.Errorf("no X.509 bundle for trust domain %q", trustDomain))
	}
	bundle := x509bundle.FromX509Authorities(trustDomain, x509Authorities)
	if err := bundleUsable(bundle, s.now()); err != nil {
		return nil, wrapBundlesourceErr(fmt.Errorf("%w: %v", ErrSourceUnready, err))
	}
	return bundle, nil
}

// GetJWTBundleForTrustDomain is unsupported: JWT trust is outside the strict
// profile and is never merged into this source.
func (s *BundleSource) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	return nil, pqprofile.Unsupported("workloadapi.BundleSource.GetJWTBundleForTrustDomain")
}

// WaitUntilUpdated waits until the source is updated or the context is done,
// in which case ctx.Err() is returned.
func (s *BundleSource) WaitUntilUpdated(ctx context.Context) error {
	return s.watcher.WaitUntilUpdated(ctx)
}

// Updated returns a channel that is sent on whenever the source is updated.
func (s *BundleSource) Updated() <-chan struct{} {
	return s.watcher.Updated()
}

func (s *BundleSource) setX509Context(x509Context *X509Context) {
	now := s.now()

	var updateErr error
	switch {
	case x509Context == nil:
		updateErr = errors.New("nil X.509 context")
	case x509Context.Bundles == nil:
		updateErr = errors.New("missing X.509 bundle set")
	default:
		updateErr = validateBundles(x509Context.Bundles, now)
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()
	if updateErr != nil {
		// Fail closed: a rejected update removes all served trust.
		s.x509Authorities = make(map[spiffeid.TrustDomain][]*x509.Certificate)
		s.life.markUnready(updateErr.Error(), now)
		return
	}

	// Apply atomically: build the replacement map first, then swap. Trust
	// domains missing from the update are removed.
	replacement := make(map[spiffeid.TrustDomain][]*x509.Certificate)
	for _, newBundle := range x509Context.Bundles.Bundles() {
		replacement[newBundle.TrustDomain()] = newBundle.X509Authorities()
	}
	s.x509Authorities = replacement
	s.life.markReady(now)
}

func (s *BundleSource) setX509ContextError(err error) {
	now := s.now()
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if err == nil {
		err = errors.New("workload API watch error")
	}
	s.life.markUnready("workload API watch error: "+err.Error(), now)
}

func (s *BundleSource) readyLocked() error {
	if err := s.life.readyErr(); err != nil {
		return err
	}
	if err := s.validateLocked(); err != nil {
		return fmt.Errorf("%w: %v", ErrSourceUnready, err)
	}
	return nil
}

func (s *BundleSource) validateLocked() error {
	set := x509bundle.NewSet()
	for trustDomain, authorities := range s.x509Authorities {
		set.Add(x509bundle.FromX509Authorities(trustDomain, authorities))
	}
	return validateBundles(set, s.now())
}

func (s *BundleSource) checkClosed() error {
	s.closeMtx.RLock()
	defer s.closeMtx.RUnlock()
	if s.closed {
		return wrapBundlesourceErr(errors.New("source is closed"))
	}
	return nil
}

func wrapBundlesourceErr(err error) error {
	return fmt.Errorf("bundlesource: %w", err)
}
