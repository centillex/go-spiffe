// pq-jwt-fetch prints a JWT-SVID from the Workload API. It is intended for
// piping into an independent JOSE verifier and never writes the token to disk.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func run() error {
	endpoint := flag.String("endpoint", "", "workload API address")
	identity := flag.String("id", "", "SPIFFE ID of the workload")
	audience := flag.String("audience", "", "JWT-SVID audience")
	timeout := flag.Duration("timeout", 10*time.Second, "fetch timeout")
	flag.Parse()
	if *endpoint == "" || *audience == "" {
		return errors.New("endpoint and audience are required")
	}
	id, err := spiffeid.FromString(*identity)
	if err != nil {
		return errors.New("valid SPIFFE ID required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(*endpoint))
	if err != nil {
		return errors.New("workload API client failed")
	}
	defer client.Close()
	svid, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Subject: id, Audience: *audience})
	if err != nil {
		return errors.New("JWT-SVID fetch failed")
	}
	_, err = fmt.Fprintln(os.Stdout, svid.Marshal())
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
