package workloadapi_test

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
)

// TestWITAPIsAreUnsupported pins the remaining token-profile boundary: WIT
// requests fail before any RPC, so there is no hidden fallback.
func TestWITAPIsAreUnsupported(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client, err := workloadapi.New(ctx, workloadapi.WithAddr("tcp://127.0.0.1:1"))
	require.NoError(t, err)
	defer client.Close()

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	id := spiffeid.RequireFromPath(td, "/workload")

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

func TestWITConvenienceAPIsAreUnsupported(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	id := spiffeid.RequireFromPath(td, "/workload")
	opts := []workloadapi.ClientOption{workloadapi.WithAddr("tcp://127.0.0.1:1")}

	_, err := workloadapi.FetchWITSVID(ctx, id.String(), opts...)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	_, err = workloadapi.FetchWITSVIDs(ctx, id.String(), opts...)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)

	_, err = workloadapi.FetchWITBundles(ctx, opts...)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
}

func TestWITSourceCannotBeConstructed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	witSource, err := workloadapi.NewWITSource(ctx)
	require.ErrorIs(t, err, pqprofile.ErrUnsupported)
	require.Nil(t, witSource)
}

type noopWITSVIDWatcher struct{}

func (noopWITSVIDWatcher) OnWITSVIDsUpdate([]*witsvid.SVID) {}

func (noopWITSVIDWatcher) OnWITSVIDsWatchError(error) {}

type noopWITBundleWatcher struct{}

func (noopWITBundleWatcher) OnWITBundlesUpdate(*witbundle.Set) {}

func (noopWITBundleWatcher) OnWITBundlesWatchError(error) {}
