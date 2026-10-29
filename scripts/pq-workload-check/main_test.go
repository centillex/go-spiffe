package main

import (
	"crypto/sha256"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
)

func TestCredentialCheck(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("deployment.example")
	id := spiffeid.RequireFromString("spiffe://deployment.example/workload")
	ca := test.NewPQCA(t, td)
	svid := ca.CreateX509SVID(id)
	pin := sha256.Sum256(ca.X509Authorities()[0].Raw)
	c := &workloadapi.X509Context{SVIDs: []*x509svid.SVID{svid}, Bundles: x509bundle.NewSet(ca.X509Bundle())}
	result, err := check(c, id, pin)
	require.NoError(t, err)
	require.Equal(t, "credential_path_verified", result.Status)
	require.False(t, result.Step6Complete)
	_, err = check(c, id, [32]byte{})
	require.ErrorContains(t, err, "pin")
	_, err = check(c, spiffeid.RequireFromString("spiffe://deployment.example/unauthorized"), pin)
	require.Error(t, err)
	_, err = check(nil, id, pin)
	require.Error(t, err)
	c.SVIDs = append(c.SVIDs, svid)
	_, err = check(c, id, pin)
	require.ErrorContains(t, err, "ambiguous")
	// A different delivered CA cannot substitute for the independently pinned CA.
	other := test.NewPQCA(t, td)
	c.SVIDs = []*x509svid.SVID{other.CreateX509SVID(id)}
	c.Bundles.Add(other.X509Bundle())
	_, err = check(c, id, pin)
	require.Error(t, err)
	// Pinning a classical authority does not exempt it from strict path policy.
	classical := test.NewCA(t, td)
	c.SVIDs = []*x509svid.SVID{classical.CreateX509SVID(id)}
	c.Bundles = x509bundle.NewSet(classical.X509Bundle())
	_, err = check(c, id, sha256.Sum256(classical.X509Authorities()[0].Raw))
	require.Error(t, err)
}

func TestExplicitLocalEndpoint(t *testing.T) {
	require.NoError(t, validateEndpoint("unix:///tmp/workload.sock"))
	for _, endpoint := range []string{"", "tcp://localhost:8081", "unix:relative", "unix://host/tmp/socket", "unix:///tmp/socket?fallback=true", "unix:///tmp/socket#fragment"} {
		require.Error(t, validateEndpoint(endpoint), endpoint)
	}
}
