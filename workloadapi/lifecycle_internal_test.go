package workloadapi

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"
)

func pqCA(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PQ lifecycle CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func newTestX509Source(now time.Time) *X509Source {
	return &X509Source{now: func() time.Time { return now }}
}

func newTestBundleSource(now time.Time) *BundleSource {
	return &BundleSource{now: func() time.Time { return now }, x509Authorities: map[spiffeid.TrustDomain][]*x509.Certificate{}}
}

func TestX509SourceLifecycleDeterministic(t *testing.T) {
	now := time.Now()
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	id := spiffeid.RequireFromPath(td, "/workload")
	ca := test.NewPQCA(t, td)
	svid := ca.CreateX509SVID(id, test.WithLifetime(now.Add(-time.Minute), now.Add(time.Hour)))

	s := newTestX509Source(now)

	// Nil context is a malformed update.
	s.setX509Context(nil)
	require.ErrorIs(t, s.Ready(), ErrSourceUnready)
	require.Contains(t, s.State().Reason, "nil X.509 context")
	require.Nil(t, s.svid)

	// Missing bundle set is rejected.
	s.setX509Context(&X509Context{SVIDs: []*x509svid.SVID{svid}})
	require.ErrorIs(t, s.Ready(), ErrSourceUnready)

	// Empty identity list is rejected.
	s.setX509Context(&X509Context{SVIDs: nil, Bundles: x509bundle.NewSet(ca.X509Bundle())})
	require.ErrorIs(t, s.Ready(), ErrSourceUnready)
	require.Contains(t, s.State().Reason, "missing X509-SVID")

	// A valid update becomes ready and atomically pairs SVID and bundles.
	s.setX509Context(&X509Context{SVIDs: []*x509svid.SVID{svid}, Bundles: x509bundle.NewSet(ca.X509Bundle())})
	require.NoError(t, s.Ready())
	snapshot, state, err := s.Snapshot()
	require.NoError(t, err)
	require.True(t, state.Ready)
	require.Equal(t, id, snapshot.SVIDs[0].ID)
	_, err = snapshot.Bundles.GetX509BundleForTrustDomain(td)
	require.NoError(t, err)

	// Watch error makes the source unready but preserves generation progress.
	generation := s.State().Generation
	s.setX509ContextError(errFakeWatch)
	require.ErrorIs(t, s.Ready(), ErrSourceUnready)
	require.Greater(t, s.State().Generation, generation)

	// Recovery.
	s.setX509Context(&X509Context{SVIDs: []*x509svid.SVID{svid}, Bundles: x509bundle.NewSet(ca.X509Bundle())})
	require.NoError(t, s.Ready())

	// The cached SVID becomes unusable after its expiry without a new update.
	s.now = func() time.Time { return now.Add(2 * time.Hour) }
	require.ErrorIs(t, s.Ready(), ErrSourceUnready)
	require.Contains(t, s.State().Reason, "expired")
	_, err = s.GetX509SVID()
	require.ErrorIs(t, err, ErrSourceUnready)
	_, _, err = s.Snapshot()
	require.ErrorIs(t, err, ErrSourceUnready)
}

func TestBundleSourceLifecycleDeterministic(t *testing.T) {
	now := time.Now()
	td := spiffeid.RequireTrustDomainFromString("domain.test")

	// An expired authority is unusable.
	expired := pqCA(t, now.Add(-2*time.Hour), now.Add(-time.Hour))
	expiredSet := x509bundle.NewSet(x509bundle.FromX509Authorities(td, []*x509.Certificate{expired}))
	s := newTestBundleSource(now)
	s.setX509Context(&X509Context{Bundles: expiredSet})
	require.ErrorIs(t, s.Ready(), ErrSourceUnready)
	require.Contains(t, s.State().Reason, "no authority valid")

	// A valid authority is accepted.
	valid := pqCA(t, now.Add(-time.Minute), now.Add(time.Hour))
	validSet := x509bundle.NewSet(x509bundle.FromX509Authorities(td, []*x509.Certificate{valid}))
	s.setX509Context(&X509Context{Bundles: validSet})
	require.NoError(t, s.Ready())
	_, err := s.GetX509BundleForTrustDomain(td)
	require.NoError(t, err)

	// The cached authority expiring makes lookups fail closed.
	s.now = func() time.Time { return now.Add(2 * time.Hour) }
	require.ErrorIs(t, s.Ready(), ErrSourceUnready)
	_, err = s.GetX509BundleForTrustDomain(td)
	require.ErrorIs(t, err, ErrSourceUnready)

	// A rejected update removes all previously served trust.
	s.now = func() time.Time { return now }
	s.setX509Context(&X509Context{Bundles: nil})
	require.ErrorIs(t, s.Ready(), ErrSourceUnready)
	require.Empty(t, s.x509Authorities)
}

var errFakeWatch = &fakeWatchError{}

type fakeWatchError struct{}

func (*fakeWatchError) Error() string { return "fake watch failure" }

// TestBundleRotationOverlapOnlyAcceptsApprovedCredentials covers rotation
// overlap: old and new authorities may coexist, but every authority must be
// approved and at least one must be currently valid.
func TestBundleRotationOverlapOnlyAcceptsApprovedCredentials(t *testing.T) {
	now := time.Now()
	td := spiffeid.RequireTrustDomainFromString("domain.test")

	oldCA := pqCA(t, now.Add(-time.Hour), now.Add(time.Hour))
	newCA := pqCA(t, now.Add(-time.Minute), now.Add(2*time.Hour))
	s := newTestBundleSource(now)

	// Overlap containing two independently valid approved authorities.
	s.setX509Context(&X509Context{Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(td, []*x509.Certificate{oldCA, newCA}))})
	require.NoError(t, s.Ready())
	bundle, err := s.GetX509BundleForTrustDomain(td)
	require.NoError(t, err)
	require.Len(t, bundle.X509Authorities(), 2)

	// After the old authority expires the source is still usable via the new one.
	s.now = func() time.Time { return now.Add(90 * time.Minute) }
	require.NoError(t, s.Ready())

	// Once only the expired authority remains, the source is unready.
	s.setX509Context(&X509Context{Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(td, []*x509.Certificate{oldCA}))})
	require.ErrorIs(t, s.Ready(), ErrSourceUnready)

	// A classical authority in an overlap is rejected outright, even alongside
	// a valid approved authority.
	classical := test.NewCA(t, td).X509Authorities()[0]
	s.now = func() time.Time { return now }
	s.setX509Context(&X509Context{Bundles: x509bundle.NewSet(x509bundle.FromX509Authorities(td, []*x509.Certificate{newCA, classical}))})
	require.ErrorIs(t, s.Ready(), ErrSourceUnready)
	require.Contains(t, s.State().Reason, "ML-DSA-65")
}
