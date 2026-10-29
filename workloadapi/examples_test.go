package workloadapi_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func ExampleFetchX509SVID() {
	svid, err := workloadapi.FetchX509SVID(context.TODO())
	if err != nil {
		// TODO: error handling
	}

	// TODO: use the X509-SVID
	_ = svid
}

// JWT-SVIDs are outside the strict profile; requests report the shared
// unsupported error instead of returning a classical token.
func ExampleFetchJWTSVID_unsupported() {
	serverID := spiffeid.RequireFromString("spiffe://example.org/server")
	_, err := workloadapi.FetchJWTSVID(context.TODO(), jwtsvid.Params{
		Audience: serverID.String(),
	})
	if errors.Is(err, pqprofile.ErrUnsupported) {
		fmt.Println("JWT-SVID is unsupported")
	}
	// Output: JWT-SVID is unsupported
}
