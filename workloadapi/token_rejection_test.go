package workloadapi_test

import (
	"context"
	"crypto/mldsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/pqjose"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
)

func TestFetchWITSVID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	id := spiffeid.RequireFromPath(td, "/workload")
	serverKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)
	workloadKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	cnfJWK, err := pqjose.MarshalPublicJWK("workload-key", workloadKey.PublicKey())
	require.NoError(t, err)
	var cnf map[string]any
	require.NoError(t, json.Unmarshal(cnfJWK, &cnf))
	claims, err := json.Marshal(map[string]any{
		"sub": id.String(),
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": cnf},
	})
	require.NoError(t, err)
	token, err := pqjose.SignJWTWithType("wit+jwt", "wit-key", claims, serverKey)
	require.NoError(t, err)

	privateJWK, err := pqjose.MarshalPrivateJWK("workload-key", workloadKey)
	require.NoError(t, err)
	api.SetWITSVIDResponse(&workload.WITSVIDResponse{
		Svids: []*workload.WITSVID{{
			SpiffeId:   id.String(),
			WitSvid:    token,
			WitSvidKey: string(privateJWK),
			Hint:       "hint",
		}},
	})
	bundle := witbundle.New(td)
	require.NoError(t, bundle.AddWITAuthority("wit-key", serverKey.PublicKey()))
	api.SetWITBundles(bundle)

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(api.Addr()))
	require.NoError(t, err)
	defer client.Close()

	svid, err := client.FetchWITSVID(ctx, id.String())
	require.NoError(t, err)
	require.Equal(t, id, svid.ID)
	require.Equal(t, "hint", svid.Hint)
	require.NotNil(t, svid.PrivateKey)
	require.True(t, svid.PublicKey.Equal(svid.PrivateKey.PublicKey()))

	validated, err := witsvid.ParseAndValidate(svid.Marshal(), bundle)
	require.NoError(t, err)
	require.Equal(t, id, validated.ID)
	require.True(t, validated.PublicKey.Equal(workloadKey.PublicKey()))

	bundles, err := client.FetchWITBundles(ctx)
	require.NoError(t, err)
	fetched, err := bundles.GetWITBundleForTrustDomain(td)
	require.NoError(t, err)
	require.True(t, fetched.HasWITAuthority("wit-key"))

	// A modified signature must not validate.
	tampered := []byte(token)
	if tampered[len(tampered)-1] == 'A' {
		tampered[len(tampered)-1] = 'B'
	} else {
		tampered[len(tampered)-1] = 'A'
	}
	_, err = witsvid.ParseAndValidate(string(tampered), bundle)
	require.ErrorContains(t, err, "signature verification failed")
}
