package jwtsvid_test

import (
	"crypto/mldsa"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/pqjose"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

func ExampleParseAndValidate() {
	key, _ := mldsa.GenerateKey(mldsa.MLDSA65())
	token, _ := pqjose.SignJWT("example-key", []byte(`{"sub":"spiffe://example.org/workload","aud":["example"],"exp":4102444800}`), key)

	bundle := jwtbundle.New(spiffeid.RequireTrustDomainFromString("example.org"))
	_ = bundle.AddJWTAuthority("example-key", key.PublicKey())

	svid, err := jwtsvid.ParseAndValidate(token, jwtbundle.NewSet(bundle), []string{"example"})
	if err != nil {
		panic(err)
	}
	fmt.Println(svid.ID)
	// Output: spiffe://example.org/workload
}
