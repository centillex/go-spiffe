package workloadapi_test

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
)

// TestTokenAPIsAreUnsupported pins the Workload API boundary: token requests
// fail with the shared sentinel before any RPC, even with a canceled context
// and an unusable address, so there is no classical fallback or hidden fetch.
func TestTokenAPIsAreUnsupported(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client, err := workloadapi.New(ctx, workloadapi.WithAddr("tcp://127.0.0.1:1"))
	require.NoError(t, err)
	defer client.Close()

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	id := spiffeid.RequireFromPath(td, "/workload")
	params := jwtsvid.Params{Subject: id, Audience: id.String()}

	jwtSVID, err := client.FetchJWTSVID(ctx, params)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
	require.Nil(t, jwtSVID)

	jwtSVIDs, err := client.FetchJWTSVIDs(ctx, params)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
	require.Nil(t, jwtSVIDs)

	jwtBundles, err := client.FetchJWTBundles(ctx)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
	require.Nil(t, jwtBundles)

	require.ErrorIs(t, client.WatchJWTBundles(ctx, noopJWTBundleWatcher{}), pqprofile.ErrUnsupported)

	validated, err := client.ValidateJWTSVID(ctx, "token", "audience")
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
	require.Nil(t, validated)

	witSVID, err := client.FetchWITSVID(ctx, id.String())
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
	require.Nil(t, witSVID)

	witSVIDs, err := client.FetchWITSVIDs(ctx, id.String())
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
	require.Nil(t, witSVIDs)

	require.ErrorIs(t, client.WatchWITSVIDs(ctx, noopWITSVIDWatcher{}, id.String()), pqprofile.ErrUnsupported)

	witBundles, err := client.FetchWITBundles(ctx)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
	require.Nil(t, witBundles)

	require.ErrorIs(t, client.WatchWITBundles(ctx, noopWITBundleWatcher{}), pqprofile.ErrUnsupported)
}

func TestConvenienceTokenAPIsAreUnsupported(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	id := spiffeid.RequireFromPath(td, "/workload")
	params := jwtsvid.Params{Subject: id, Audience: id.String()}
	opts := []workloadapi.ClientOption{workloadapi.WithAddr("tcp://127.0.0.1:1")}

	_, err := workloadapi.FetchJWTSVID(ctx, params, opts...)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	_, err = workloadapi.FetchJWTSVIDs(ctx, params, opts...)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	_, err = workloadapi.FetchJWTBundles(ctx, opts...)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	err = workloadapi.WatchJWTBundles(ctx, noopJWTBundleWatcher{}, opts...)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	_, err = workloadapi.ValidateJWTSVID(ctx, "token", "audience", opts...)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	_, err = workloadapi.FetchWITSVID(ctx, id.String(), opts...)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	_, err = workloadapi.FetchWITSVIDs(ctx, id.String(), opts...)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	_, err = workloadapi.FetchWITBundles(ctx, opts...)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
}

func TestTokenSourcesCannotBeConstructed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	jwtSource, err := workloadapi.NewJWTSource(ctx)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
	require.Nil(t, jwtSource)

	witSource, err := workloadapi.NewWITSource(ctx)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
	require.Nil(t, witSource)
}

type noopJWTBundleWatcher struct{}

func (noopJWTBundleWatcher) OnJWTBundlesUpdate(*jwtbundle.Set) {}

func (noopJWTBundleWatcher) OnJWTBundlesWatchError(error) {}

type noopWITSVIDWatcher struct{}

func (noopWITSVIDWatcher) OnWITSVIDsUpdate([]*witsvid.SVID) {}

func (noopWITSVIDWatcher) OnWITSVIDsWatchError(error) {}

type noopWITBundleWatcher struct{}

func (noopWITBundleWatcher) OnWITBundlesUpdate(*witbundle.Set) {}

func (noopWITBundleWatcher) OnWITBundlesWatchError(error) {}
