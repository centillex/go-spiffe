package federation

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

// FetchOption is an option used when dialing the bundle endpoint.
type FetchOption interface {
	apply(*fetchOptions) error
}

type fetchOptions struct {
	transport  *http.Transport
	authMethod authMethod
}

// WithSPIFFEAuth authenticates the bundle endpoint with SPIFFE authentication
// using the provided root store. It validates that the endpoint presents the
// expected SPIFFE ID. This option cannot be used in conjuntion with WithWebPKIRoots
// option.
func WithSPIFFEAuth(bundleSource x509bundle.Source, endpointID spiffeid.ID) FetchOption {
	return fetchOption(func(o *fetchOptions) error {
		if o.authMethod != authMethodDefault {
			return wrapFederationErr(errors.New("cannot use both SPIFFE and Web PKI authentication"))
		}
		o.transport.DialTLSContext = tlsconfig.TLSClientConfig(bundleSource, tlsconfig.AuthorizeID(endpointID)).DialContext
		o.authMethod = authMethodSPIFFE
		return nil
	})
}

// WithWebPKIRoots authenticates the bundle endpoint using Web PKI authentication
// using the provided X.509 root certificates instead of the system ones. This option
// cannot be used in conjuntion with WithSPIFFEAuth option.
func WithWebPKIRoots(rootCAs *x509.CertPool) FetchOption {
	return fetchOption(func(o *fetchOptions) error {
		if o.authMethod != authMethodDefault {
			return wrapFederationErr(errors.New("cannot use both SPIFFE and Web PKI authentication"))
		}
		o.transport.DialTLSContext = tlsconfig.WebClientConfig(rootCAs).DialContext
		o.authMethod = authMethodWebPKI
		return nil
	})
}

// FetchBundle retrieves strict-profile X.509 trust from an authenticated HTTPS
// bundle endpoint. JWT/WIT and unknown-use entries are discarded, not admitted
// as token trust. Recognized classical X.509 authorities are rejected. The caller
// must associate trustDomain with the configured authenticated endpoint.
func FetchBundle(ctx context.Context, trustDomain spiffeid.TrustDomain, url string, option ...FetchOption) (*spiffebundle.Bundle, error) {
	opts := fetchOptions{
		transport: &http.Transport{},
	}
	// Do not inherit mutable global transports, proxies, or TLS dial callbacks.
	opts.transport.DialTLSContext = tlsconfig.WebClientConfig(nil).DialContext
	defer opts.transport.CloseIdleConnections()
	for _, o := range option {
		if err := o.apply(&opts); err != nil {
			return nil, err
		}
	}

	var client = &http.Client{
		Transport: opts.transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return wrapFederationErr(errors.New("bundle endpoint redirects are not permitted"))
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, wrapFederationErr(fmt.Errorf("could not create request: %w", err))
	}
	if request.URL.Scheme != "https" || request.URL.Host == "" {
		return nil, wrapFederationErr(errors.New("bundle endpoint must use HTTPS"))
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, wrapFederationErr(fmt.Errorf("could not GET bundle: %w", err))
	}
	defer response.Body.Close()

	bundle, err := spiffebundle.ReadX509Only(trustDomain, response.Body)
	if err != nil {
		return nil, wrapFederationErr(err)
	}

	return bundle, nil
}

func wrapFederationErr(err error) error {
	return fmt.Errorf("federation: %w", err)
}

type fetchOption func(*fetchOptions) error

func (fo fetchOption) apply(opts *fetchOptions) error {
	return fo(opts)
}

type authMethod int

const (
	authMethodDefault authMethod = iota
	authMethodSPIFFE
	authMethodWebPKI
)
