package workloadapi_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
)

func pqContext(t *testing.T, td spiffeid.TrustDomain, id spiffeid.ID) *fakeworkloadapi.X509SVIDResponse {
	t.Helper()
	ca := test.NewPQCA(t, td)
	return &fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{ca.CreateX509SVID(id)},
		Bundle: ca.X509Bundle(),
	}
}

func waitReady(t *testing.T, source *workloadapi.X509Source, wantReady bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		err := source.Ready()
		if (err == nil) == wantReady {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("source readiness did not become %v: %v", wantReady, source.Ready())
}

// TestX509SourceReadinessAndRecovery checks that an invalid update fails closed
// and that a later valid update restores service without a restart.
func TestX509SourceReadinessAndRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	id := spiffeid.RequireFromPath(td, "/workload")
	api.SetX509SVIDResponse(pqContext(t, td, id))

	source, err := workloadapi.NewX509Source(ctx, withAddr(api))
	require.NoError(t, err)
	defer source.Close()
	require.NoError(t, source.Ready())
	require.Equal(t, uint64(1), source.State().Generation)

	// An update with no identity is invalid for this profile: the source must
	// become unready and stop serving the previous SVID.
	ca := test.NewPQCA(t, td)
	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{SVIDs: nil, Bundle: ca.X509Bundle()})
	waitReady(t, source, false)
	require.ErrorIs(t, source.Ready(), workloadapi.ErrSourceUnready)
	_, err = source.GetX509SVID()
	require.ErrorIs(t, err, workloadapi.ErrSourceUnready)
	_, _, err = source.Snapshot()
	require.ErrorIs(t, err, workloadapi.ErrSourceUnready)
	state := source.State()
	require.False(t, state.Ready)
	require.NotEmpty(t, state.Reason)
	require.Equal(t, uint64(2), state.Generation)

	// A valid update recovers the source.
	api.SetX509SVIDResponse(pqContext(t, td, id))
	require.NoError(t, source.WaitUntilUpdated(ctx))
	require.NoError(t, source.Ready())
	svid, err := source.GetX509SVID()
	require.NoError(t, err)
	require.Equal(t, id, svid.ID)
	require.Equal(t, uint64(3), source.State().Generation)
}

// TestX509SourceRejectsDowngrade pins downgrade rejection: a classical update
// makes the source unready, and recovery requires an approved update.
func TestX509SourceRejectsDowngrade(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	id := spiffeid.RequireFromPath(td, "/workload")
	api.SetX509SVIDResponse(pqContext(t, td, id))

	source, err := workloadapi.NewX509Source(ctx, withAddr(api))
	require.NoError(t, err)
	defer source.Close()
	require.NoError(t, source.Ready())

	classicalCA := test.NewCA(t, td)
	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{classicalCA.CreateX509SVID(id)},
		Bundle: classicalCA.X509Bundle(),
	})
	require.NoError(t, source.WaitUntilUpdated(ctx))
	require.ErrorIs(t, source.Ready(), workloadapi.ErrSourceUnready)
	require.Contains(t, source.State().Reason, "ML-DSA-65")
	_, err = source.GetX509SVID()
	require.ErrorIs(t, err, workloadapi.ErrSourceUnready)

	api.SetX509SVIDResponse(pqContext(t, td, id))
	require.NoError(t, source.WaitUntilUpdated(ctx))
	require.NoError(t, source.Ready())
}

// TestX509SourceBecomesUnreadyOnSourceLoss simulates the Workload API going
// away: the source must stop serving cached credentials.
func TestX509SourceBecomesUnreadyOnSourceLoss(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	id := spiffeid.RequireFromPath(td, "/workload")
	api.SetX509SVIDResponse(pqContext(t, td, id))

	source, err := workloadapi.NewX509Source(ctx, withAddr(api))
	require.NoError(t, err)
	defer source.Close()
	require.NoError(t, source.Ready())

	api.Stop()
	waitReady(t, source, false)
	_, err = source.GetX509SVID()
	require.ErrorIs(t, err, workloadapi.ErrSourceUnready)
	require.Contains(t, source.State().Reason, "watch error")
}

// TestBundleSourceLifecycle covers trust removal, re-addition, downgrade
// rejection, and recovery.
func TestBundleSourceLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	td1 := spiffeid.RequireTrustDomainFromString("domain1.test")
	td2 := spiffeid.RequireTrustDomainFromString("domain2.test")
	id := spiffeid.RequireFromPath(td1, "/workload")
	ca1 := test.NewPQCA(t, td1)
	ca2 := test.NewPQCA(t, td2)

	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:            []*x509svid.SVID{ca1.CreateX509SVID(id)},
		Bundle:           ca1.X509Bundle(),
		FederatedBundles: []*x509bundle.Bundle{ca2.X509Bundle()},
	})
	source, err := workloadapi.NewBundleSource(ctx, withAddr(api))
	require.NoError(t, err)
	defer source.Close()
	require.NoError(t, source.Ready())

	_, err = source.GetX509BundleForTrustDomain(td1)
	require.NoError(t, err)
	_, err = source.GetX509BundleForTrustDomain(td2)
	require.NoError(t, err)

	// Trust removal: domain2 disappears from the update.
	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{ca1.CreateX509SVID(id)},
		Bundle: ca1.X509Bundle(),
	})
	require.NoError(t, source.WaitUntilUpdated(ctx))
	require.NoError(t, source.Ready())
	_, err = source.GetX509BundleForTrustDomain(td2)
	require.Error(t, err)
	require.NotErrorIs(t, err, workloadapi.ErrSourceUnready)

	// Downgrade: a classical trust domain makes the whole source unready.
	classical := test.NewCA(t, td2)
	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:            []*x509svid.SVID{ca1.CreateX509SVID(id)},
		Bundle:           ca1.X509Bundle(),
		FederatedBundles: []*x509bundle.Bundle{classical.X509Bundle()},
	})
	require.NoError(t, source.WaitUntilUpdated(ctx))
	require.ErrorIs(t, source.Ready(), workloadapi.ErrSourceUnready)
	_, err = source.GetX509BundleForTrustDomain(td1)
	require.ErrorIs(t, err, workloadapi.ErrSourceUnready)

	// Recovery restores the approved trust and re-adds domain2.
	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:            []*x509svid.SVID{ca1.CreateX509SVID(id)},
		Bundle:           ca1.X509Bundle(),
		FederatedBundles: []*x509bundle.Bundle{ca2.X509Bundle()},
	})
	require.NoError(t, source.WaitUntilUpdated(ctx))
	require.NoError(t, source.Ready())
	_, err = source.GetX509BundleForTrustDomain(td2)
	require.NoError(t, err)
}

// TestX509SourceAtomicSnapshots runs concurrent updates and readers. Every
// snapshot must pair an SVID with the bundle set from the same generation.
func TestX509SourceAtomicSnapshots(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	tdA := spiffeid.RequireTrustDomainFromString("a.test")
	tdB := spiffeid.RequireTrustDomainFromString("b.test")
	caA := test.NewPQCA(t, tdA)
	caB := test.NewPQCA(t, tdB)
	svidA := caA.CreateX509SVID(spiffeid.RequireFromPath(tdA, "/app"))
	svidB := caB.CreateX509SVID(spiffeid.RequireFromPath(tdB, "/app"))

	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{SVIDs: []*x509svid.SVID{svidA}, Bundle: caA.X509Bundle()})
	source, err := workloadapi.NewX509Source(ctx, withAddr(api))
	require.NoError(t, err)
	defer source.Close()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				snapshot, _, err := source.Snapshot()
				if err != nil {
					// The source is always ready in this test; a failure here
					// indicates a torn or rejected update.
					t.Errorf("snapshot failed: %v", err)
					return
				}
				if len(snapshot.SVIDs) != 1 {
					t.Error("snapshot missing SVID")
					return
				}
				svid := snapshot.SVIDs[0]
				if _, err := snapshot.Bundles.GetX509BundleForTrustDomain(svid.ID.TrustDomain()); err != nil {
					t.Errorf("snapshot SVID %s lacks its own trust domain bundle: %v", svid.ID, err)
					return
				}
			}
		}()
	}

	for i := 0; i < 50; i++ {
		var resp *fakeworkloadapi.X509SVIDResponse
		if i%2 == 0 {
			resp = &fakeworkloadapi.X509SVIDResponse{SVIDs: []*x509svid.SVID{svidB}, Bundle: caB.X509Bundle()}
		} else {
			resp = &fakeworkloadapi.X509SVIDResponse{SVIDs: []*x509svid.SVID{svidA}, Bundle: caA.X509Bundle()}
		}
		api.SetX509SVIDResponse(resp)
		require.NoError(t, source.WaitUntilUpdated(ctx))
		require.NoError(t, source.Ready())
	}
	close(stop)
	wg.Wait()
}

// TestX509SourceConcurrentReadsDuringUpdates exercises read/update concurrency
// for the race detector without asserting rejection behavior.
func TestX509SourceConcurrentReadsDuringUpdates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	id := spiffeid.RequireFromPath(td, "/workload")
	ca := test.NewPQCA(t, td)
	resp := &fakeworkloadapi.X509SVIDResponse{SVIDs: []*x509svid.SVID{ca.CreateX509SVID(id)}, Bundle: ca.X509Bundle()}
	api.SetX509SVIDResponse(resp)

	source, err := workloadapi.NewX509Source(ctx, withAddr(api))
	require.NoError(t, err)
	defer source.Close()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, err := source.GetX509SVID()
				if err != nil && !errors.Is(err, workloadapi.ErrSourceUnready) {
					t.Errorf("unexpected error: %v", err)
					return
				}
				_ = source.State()
				_ = source.Ready()
			}
		}()
	}
	for i := 0; i < 25; i++ {
		api.SetX509SVIDResponse(resp)
	}
	close(stop)
	wg.Wait()
}
