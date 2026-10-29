package workloadapi_test

import (
	"context"

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
