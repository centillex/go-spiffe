package workloadapi

import (
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/pqpolicy"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// ErrSourceUnready is wrapped by readiness and lookup errors when a source has
// no currently valid, profile-compliant Workload API state. Use errors.Is.
var ErrSourceUnready = errors.New("workloadapi: source is not ready")

// SourceState is an immutable snapshot of a source's lifecycle state.
type SourceState struct {
	// Ready reports whether the last applied update was valid and is still
	// usable at the time State was called.
	Ready bool
	// Reason is empty when Ready is true, otherwise it explains why the
	// source is unready.
	Reason string
	// Generation increments on every applied update, including updates that
	// were rejected and made the source unready.
	Generation uint64
	// UpdatedAt is when the last update was received.
	UpdatedAt time.Time
}

type sourceLifecycle struct {
	ready      bool
	reason     string
	generation uint64
	updatedAt  time.Time
}

func (l *sourceLifecycle) markReady(now time.Time) {
	l.ready = true
	l.reason = ""
	l.generation++
	l.updatedAt = now
}

func (l *sourceLifecycle) markUnready(reason string, now time.Time) {
	l.ready = false
	l.reason = reason
	l.generation++
	l.updatedAt = now
}

func (l *sourceLifecycle) state() SourceState {
	return SourceState{Ready: l.ready, Reason: l.reason, Generation: l.generation, UpdatedAt: l.updatedAt}
}

func (l *sourceLifecycle) readyErr() error {
	if l.ready {
		return nil
	}
	if l.reason == "" {
		return ErrSourceUnready
	}
	return fmt.Errorf("%w: %s", ErrSourceUnready, l.reason)
}

// validateSVID checks the profile-admission and lifetime properties of a
// delivered X509-SVID. It re-derives certificates from signed DER and does not
// perform path verification or authorization.
func validateSVID(svid *x509svid.SVID, now time.Time) error {
	if svid == nil {
		return errors.New("missing X509-SVID")
	}
	if len(svid.Certificates) == 0 {
		return errors.New("X509-SVID has no certificates")
	}
	certs, err := pqpolicy.ParseCertificates(svid.Certificates)
	if err != nil {
		return err
	}
	for _, cert := range certs {
		if err := pqpolicy.CheckCertificate(cert); err != nil {
			return fmt.Errorf("X509-SVID is not profile-compliant: %w", err)
		}
	}
	leaf := certs[0]
	if leaf.IsCA {
		return errors.New("X509-SVID leaf is a CA")
	}
	if now.Before(leaf.NotBefore) {
		return errors.New("X509-SVID is not yet valid")
	}
	if !now.Before(leaf.NotAfter) {
		return errors.New("X509-SVID is expired")
	}
	return nil
}

// validateBundles checks that a delivered bundle set is usable: every authority
// is profile-compliant, and each trust domain retains at least one authority
// valid at now.
func validateBundles(set *x509bundle.Set, now time.Time) error {
	if set == nil {
		return errors.New("missing X.509 bundle set")
	}
	bundles := set.Bundles()
	if len(bundles) == 0 {
		return errors.New("X.509 bundle set is empty")
	}
	for _, bundle := range bundles {
		if err := validateBundle(bundle, now); err != nil {
			return err
		}
	}
	return nil
}

func validateBundle(bundle *x509bundle.Bundle, now time.Time) error {
	if bundle == nil {
		return errors.New("nil X.509 bundle")
	}
	authorities, err := pqpolicy.ParseCertificates(bundle.X509Authorities())
	if err != nil {
		return fmt.Errorf("bundle %q: %w", bundle.TrustDomain(), err)
	}
	if len(authorities) == 0 {
		return fmt.Errorf("bundle %q has no X.509 authorities", bundle.TrustDomain())
	}
	usable := false
	for _, cert := range authorities {
		if err := pqpolicy.CheckCertificate(cert); err != nil {
			return fmt.Errorf("bundle %q: %w", bundle.TrustDomain(), err)
		}
		if !now.Before(cert.NotBefore) && now.Before(cert.NotAfter) {
			usable = true
		}
	}
	if !usable {
		return fmt.Errorf("bundle %q has no authority valid at %s", bundle.TrustDomain(), now.UTC().Format(time.RFC3339))
	}
	return nil
}

// bundleUsable reports whether the bundle still has a currently valid,
// profile-compliant authority. It is evaluated on delivery, not continuously.
func bundleUsable(bundle *x509bundle.Bundle, now time.Time) error {
	return validateBundle(bundle, now)
}
