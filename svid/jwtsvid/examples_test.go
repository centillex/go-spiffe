package jwtsvid_test

import (
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

// JWT-SVIDs are outside the strict profile, so validation reports the shared
// unsupported error instead of accepting a classical token.
func ExampleParseAndValidate() {
	_, err := jwtsvid.ParseAndValidate("TODO", jwtbundle.NewSet(), []string{"audience"})
	if errors.Is(err, pqprofile.ErrUnsupported) {
		fmt.Println("JWT-SVID is unsupported")
	}
	// Output: JWT-SVID is unsupported
}
