package workloadapi

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// X509Source is a source of X509-SVIDs and X.509 bundles maintained via the
// Workload API.
//
// Updates are validated and applied atomically. A malformed, profile-violating,
// empty, or expired update, or a Workload API watch error, makes the source
// unready: lookups then fail instead of serving stale credentials. The next
// valid update makes it ready again.
type X509Source struct {
	watcher *watcher
	picker  func([]*x509svid.SVID) *x509svid.SVID
	now     func() time.Time

	mtx     sync.RWMutex
	svid    *x509svid.SVID
	bundles *x509bundle.Set
	life    sourceLifecycle

	closeMtx sync.RWMutex
	closed   bool
}

// NewX509Source creates a new X509Source. It blocks until the initial update
// has been received from the Workload API. The source should be closed when
// no longer in use to free underlying resources.
//
// An invalid initial update does not fail construction; the source starts
// unready and reports the reason from Ready/State.
func NewX509Source(ctx context.Context, options ...X509SourceOption) (_ *X509Source, err error) {
	config := &x509SourceConfig{}
	for _, option := range options {
		option.configureX509Source(config)
	}

	s := &X509Source{
		picker: config.picker,
		now:    time.Now,
	}

	s.watcher, err = newWatcher(ctx, config.watcher, s.setX509Context, s.setX509ContextError, nil)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Close closes the source, dropping the connection to the Workload API.
// Other source methods will return an error after Close has been called.
// The underlying Workload API client will also be closed if it is owned by
// the X509Source (i.e. not provided via the WithClient option).
func (s *X509Source) Close() (err error) {
	s.closeMtx.Lock()
	s.closed = true
	s.closeMtx.Unlock()

	return s.watcher.Close()
}

// Ready returns nil when the source holds a currently valid, profile-compliant
// update and ErrSourceUnready (possibly wrapped with a reason) otherwise.
func (s *X509Source) Ready() error {
	if err := s.checkClosed(); err != nil {
		return err
	}

	s.mtx.RLock()
	defer s.mtx.RUnlock()

	if err := s.life.readyErr(); err != nil {
		return wrapX509sourceErr(err)
	}
	// A cached credential can expire between updates.
	if s.svid == nil {
		return wrapX509sourceErr(fmt.Errorf("%w: missing X509-SVID", ErrSourceUnready))
	}
	if err := validateSVID(s.svid, s.now()); err != nil {
		return wrapX509sourceErr(fmt.Errorf("%w: %v", ErrSourceUnready, err))
	}
	return nil
}

// State returns an immutable snapshot of the source lifecycle state.
func (s *X509Source) State() SourceState {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	state := s.life.state()
	if state.Ready && s.svid != nil {
		if err := validateSVID(s.svid, s.now()); err != nil {
			state.Ready = false
			state.Reason = err.Error()
		}
	}
	return state
}

// Snapshot returns an atomically consistent view of the selected X509-SVID and
// the full bundle set that accompanied it. This avoids mixing an SVID from one
// update with bundles from another.
func (s *X509Source) Snapshot() (*X509Context, SourceState, error) {
	if err := s.checkClosed(); err != nil {
		return nil, SourceState{}, err
	}

	s.mtx.RLock()
	defer s.mtx.RUnlock()

	state := s.life.state()
	if err := s.life.readyErr(); err != nil {
		return nil, state, wrapX509sourceErr(err)
	}
	now := s.now()
	if err := validateSVID(s.svid, now); err != nil {
		state.Ready = false
		state.Reason = err.Error()
		return nil, state, wrapX509sourceErr(fmt.Errorf("%w: %v", ErrSourceUnready, err))
	}
	if err := validateBundles(s.bundles, now); err != nil {
		state.Ready = false
		state.Reason = err.Error()
		return nil, state, wrapX509sourceErr(fmt.Errorf("%w: %v", ErrSourceUnready, err))
	}
	return &X509Context{SVIDs: []*x509svid.SVID{s.svid}, Bundles: s.bundles}, state, nil
}

// GetX509SVID returns an X509-SVID from the source. It implements the
// x509svid.Source interface.
func (s *X509Source) GetX509SVID() (*x509svid.SVID, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}

	s.mtx.RLock()
	defer s.mtx.RUnlock()

	if err := s.life.readyErr(); err != nil {
		return nil, wrapX509sourceErr(err)
	}
	if err := validateSVID(s.svid, s.now()); err != nil {
		return nil, wrapX509sourceErr(fmt.Errorf("%w: %v", ErrSourceUnready, err))
	}
	return s.svid, nil
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain. It implements the x509bundle.Source interface.
func (s *X509Source) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	if err := s.checkClosed(); err != nil {
		return nil, err
	}

	s.mtx.RLock()
	defer s.mtx.RUnlock()

	if err := s.life.readyErr(); err != nil {
		return nil, wrapX509sourceErr(err)
	}
	if s.bundles == nil {
		return nil, wrapX509sourceErr(fmt.Errorf("%w: missing X.509 bundle set", ErrSourceUnready))
	}
	bundle, err := s.bundles.GetX509BundleForTrustDomain(trustDomain)
	if err != nil {
		return nil, err
	}
	if err := bundleUsable(bundle, s.now()); err != nil {
		return nil, wrapX509sourceErr(fmt.Errorf("%w: %v", ErrSourceUnready, err))
	}
	return bundle, nil
}

// WaitUntilUpdated waits until the source is updated or the context is done,
// in which case ctx.Err() is returned.
func (s *X509Source) WaitUntilUpdated(ctx context.Context) error {
	return s.watcher.WaitUntilUpdated(ctx)
}

// Updated returns a channel that is sent on whenever the source is updated.
func (s *X509Source) Updated() <-chan struct{} {
	return s.watcher.Updated()
}

func (s *X509Source) setX509Context(x509Context *X509Context) {
	now := s.now()

	var svid *x509svid.SVID
	var updateErr error
	switch {
	case x509Context == nil:
		updateErr = errors.New("nil X.509 context")
	case x509Context.Bundles == nil:
		updateErr = errors.New("missing X.509 bundle set")
	default:
		if s.picker == nil {
			if len(x509Context.SVIDs) != 0 {
				svid = x509Context.SVIDs[0]
			}
		} else {
			svid = s.picker(x509Context.SVIDs)
		}
		if err := validateSVID(svid, now); err != nil {
			updateErr = err
		} else if err := validateBundles(x509Context.Bundles, now); err != nil {
			updateErr = err
		}
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()
	if updateErr != nil {
		// Fail closed: do not expose credentials from a rejected update.
		s.svid = nil
		s.bundles = nil
		s.life.markUnready(updateErr.Error(), now)
		return
	}
	s.svid = svid
	s.bundles = x509Context.Bundles
	s.life.markReady(now)
}

func (s *X509Source) setX509ContextError(err error) {
	now := s.now()
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if err == nil {
		err = errors.New("workload API watch error")
	}
	s.life.markUnready("workload API watch error: "+err.Error(), now)
}

func (s *X509Source) checkClosed() error {
	s.closeMtx.RLock()
	defer s.closeMtx.RUnlock()
	if s.closed {
		return wrapX509sourceErr(errors.New("source is closed"))
	}
	return nil
}

func wrapX509sourceErr(err error) error {
	return fmt.Errorf("x509source: %w", err)
}
