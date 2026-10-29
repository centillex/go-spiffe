package workloadapi_test

import (
	"context"
	"crypto/mldsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/internal/test/fakeworkloadapi"
	"github.com/spiffe/go-spiffe/v2/pqjose"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
)

func TestFetchAndValidateJWTSVID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	api := fakeworkloadapi.New(t)
	defer api.Stop()

	td := spiffeid.RequireTrustDomainFromString("domain.test")
	id := spiffeid.RequireFromPath(td, "/workload")
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	claims, err := json.Marshal(map[string]any{
		"sub": id.String(),
		"aud": []string{"audience.test"},
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	token, err := pqjose.SignJWT("jwt-key", claims, key)
	require.NoError(t, err)

	api.SetJWTSVIDResponse(&workload.JWTSVIDResponse{
		Svids: []*workload.JWTSVID{{SpiffeId: id.String(), Svid: token, Hint: "hint"}},
	})
	bundle := jwtbundle.New(td)
	require.NoError(t, bundle.AddJWTAuthority("jwt-key", key.PublicKey()))
	api.SetJWTBundles(bundle)

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(api.Addr()))
	require.NoError(t, err)
	defer client.Close()

	svid, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Subject: id, Audience: "audience.test"})
	require.NoError(t, err)
	require.Equal(t, id, svid.ID)
	require.Equal(t, "hint", svid.Hint)

	bundles, err := client.FetchJWTBundles(ctx)
	require.NoError(t, err)
	fetched, err := bundles.GetJWTBundleForTrustDomain(td)
	require.NoError(t, err)
	require.True(t, fetched.HasJWTAuthority("jwt-key"))

	validated, err := client.ValidateJWTSVID(ctx, token, "audience.test")
	require.NoError(t, err)
	require.Equal(t, id, validated.ID)
}
