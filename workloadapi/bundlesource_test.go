package workloadapi_test

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBundleSourceDoesNotReturnUntilInitialUpdate(t *testing.T) {
	api := fakeworkloadapi.New(t)
	defer api.Stop()

	// Using a timeout here to detect that it doesn't return isn't ideal. Not
	// sure how to deterministically test it otherwise.
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*500)
	defer cancel()

	// Create the source. It will wait for the initial response.
	source, err := workloadapi.NewBundleSource(ctx, withAddr(api))
	if !assert.EqualError(t, err, context.DeadlineExceeded.Error()) {
		source.Close()
	}
}

func TestBundleSourceFailsCallsIfClosed(t *testing.T) {
	// Time out the test after a minute if something goes wrong.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)

	// Set the initial response, containing both X.509 and JWT materials.
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))
	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{svid},
		Bundle: ca.X509Bundle(),
	})

	// Create the source. It will wait for the initial response.
	source, err := workloadapi.NewBundleSource(ctx, withAddr(api))
	require.NoError(t, err)

	// Close the source
	require.NoError(t, source.Close())

	_, err = source.GetBundleForTrustDomain(td)
	require.EqualError(t, err, "bundlesource: source is closed")

	_, err = source.GetX509BundleForTrustDomain(td)
	require.EqualError(t, err, "bundlesource: source is closed")

	_, err = source.GetJWTBundleForTrustDomain(td)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
}

func TestBundleSourceGetsUpdates(t *testing.T) {
	// Time out the test after a minute if something goes wrong.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	// Set up the CA for a few trust domains
	domain1TD := spiffeid.RequireTrustDomainFromString("domain1.test")
	domain1CA := test.NewCA(t, domain1TD)
	domain1Bundle := domain1CA.Bundle()
	domain1X509Bundle := domain1CA.X509Bundle()

	domain2TD := spiffeid.RequireTrustDomainFromString("domain2.test")
	domain2CA := test.NewCA(t, domain2TD)
	domain2Bundle := domain2CA.Bundle()
	domain2X509Bundle := domain2CA.X509Bundle()

	svids := []*x509svid.SVID{
		domain1CA.CreateX509SVID(spiffeid.RequireFromPath(domain1TD, "/workload")),
	}

	// Set the initial response
	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:            svids,
		Bundle:           domain1X509Bundle,
		FederatedBundles: []*x509bundle.Bundle{domain2X509Bundle},
	})

	// Create the source. It will wait for the initial response.
	source, sourceDone := newBundleSource(ctx, t, api)
	defer sourceDone()

	// Assert expected bundle contents.
	requireBundle(t, source, domain1TD, domain1Bundle)
	requireX509Bundle(t, source, domain1TD, domain1X509Bundle)
	requireBundle(t, source, domain2TD, domain2Bundle)
	requireX509Bundle(t, source, domain2TD, domain2X509Bundle)

	// Now send an X.509 update that no longer provides the domain2.test
	// federated bundle. The source only watches X.509 updates.
	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  svids,
		Bundle: domain1X509Bundle,
	})
	require.NoError(t, source.WaitUntilUpdated(ctx))

	// Assert that:
	// - domain1.test SPIFFE bundle only has the X.509 authorities
	// - domain1.test X.509 bundle is available
	// - domain1.test JWT bundle is not available
	requireBundle(t, source, domain1TD, spiffebundle.FromX509Bundle(domain1X509Bundle))
	requireX509Bundle(t, source, domain1TD, domain1X509Bundle)
	requireNoBundle(t, source, domain2TD, `bundlesource: no SPIFFE bundle for trust domain "domain2.test"`)
	requireNoX509Bundle(t, source, domain2TD, `bundlesource: no X.509 bundle for trust domain "domain2.test"`)
}

func TestBundleSourceDoesNotReturnX509BundleIfMissingFromX509Response(t *testing.T) {
	// Time out the test after a minute if something goes wrong.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	domain1TD := spiffeid.RequireTrustDomainFromString("domain1.test")
	domain1CA := test.NewCA(t, domain1TD)
	domain1X509Bundle := domain1CA.X509Bundle()

	domain2TD := spiffeid.RequireTrustDomainFromString("domain2.test")

	// X509SVIDResponse's are rejected if there is no bundle, so we'll use
	// two trust domains for the test and just not set an X.509 bundle
	// for the domain2.test domain.
	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{domain1CA.CreateX509SVID(spiffeid.RequireFromPath(domain1TD, "/workload"))},
		Bundle: domain1X509Bundle,
	})

	// Create the source. It will wait for the initial response.
	source, sourceDone := newBundleSource(ctx, t, api)
	defer sourceDone()

	// Assert that the domain2.test X.509 bundle is absent: this source only
	// serves X.509 authorities.
	requireNoX509Bundle(t, source, domain2TD, `bundlesource: no X.509 bundle for trust domain "domain2.test"`)
	requireNoBundle(t, source, domain2TD, `bundlesource: no SPIFFE bundle for trust domain "domain2.test"`)
}

func TestBundleSourceRejectsJWTBundleLookups(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	api.SetX509SVIDResponse(&fakeworkloadapi.X509SVIDResponse{
		SVIDs:  []*x509svid.SVID{ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/workload"))},
		Bundle: ca.X509Bundle(),
	})

	source, sourceDone := newBundleSource(ctx, t, api)
	defer sourceDone()

	bundle, err := source.GetJWTBundleForTrustDomain(td)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
	require.Nil(t, bundle)
}

func newBundleSource(ctx context.Context, tb testing.TB, api *fakeworkloadapi.WorkloadAPI) (*workloadapi.BundleSource, func()) {
	source, err := workloadapi.NewBundleSource(ctx, withAddr(api))
	require.NoError(tb, err)
	return source, func() {
		assert.NoError(tb, source.Close())
	}
}
