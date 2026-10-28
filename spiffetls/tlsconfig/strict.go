package tlsconfig

import (
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/cryptoutil"
	"github.com/spiffe/go-spiffe/v2/internal/pqpolicy"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func profileError(message string) error { return fmt.Errorf("%s: %s", pqpolicy.ID, message) }

// installConnectionPolicy installs authentication on private configs owned by
// Config. Neither these callbacks nor their TLS state are exposed for mutation.
func installConnectionPolicy(config *tls.Config, bundle x509bundle.Source, authorizer Authorizer, peerUsage x509.ExtKeyUsage, requireLocal, webPeer, noPeer bool) {
	previousPeer := config.VerifyPeerCertificate
	previousConnection := config.VerifyConnection
	config.VerifyPeerCertificate = nil
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if err := pqpolicy.CheckTLS(state); err != nil {
			return err
		}
		// On clients VerifyConnection runs before the client certificate is sent.
		// Local client credentials are checked in GetClientCertificate; callers
		// requiring proof of mutual exchange must also inspect the final state.
		if requireLocal && peerUsage == x509.ExtKeyUsageClientAuth {
			localUsage := x509.ExtKeyUsageClientAuth
			if peerUsage == x509.ExtKeyUsageClientAuth {
				localUsage = x509.ExtKeyUsageServerAuth
			}
			if _, err := checkPresentedChain(state.LocalCertificate, localUsage); err != nil {
				return err
			}
		}
		var approved [][]*x509.Certificate
		if !noPeer {
			if len(state.PeerCertificates) == 0 {
				return profileError("peer certificate is required")
			}
			if webPeer {
				for _, chain := range state.VerifiedChains {
					if pqpolicy.CheckPath(chain, peerUsage) == nil && checkCurrentValidity(chain) == nil {
						approved = append(approved, chain)
					}
				}
				if len(approved) == 0 {
					return profileError("no approved Web PKI certification path")
				}
			} else {
				if authorizer == nil {
					return profileError("authorizer is required")
				}
				id, chains, err := x509svid.Verify(state.PeerCertificates, bundle, x509svid.WithKeyUsage(peerUsage))
				if err != nil {
					return err
				}
				if err := authorizer(id, snapshotChains(chains)); err != nil {
					return err
				}
				approved = chains
			}
			if previousPeer != nil {
				raw := make([][]byte, len(state.PeerCertificates))
				for i, cert := range state.PeerCertificates {
					raw[i] = cert.Raw
				}
				if err := previousPeer(snapshotBytes(raw), snapshotChains(approved)); err != nil {
					return err
				}
			}
		}
		if previousConnection != nil {
			state.VerifiedChains = approved
			return previousConnection(snapshotState(state))
		}
		return nil
	}
}

func checkCurrentValidity(chain []*x509.Certificate) error {
	now := time.Now()
	for _, cert := range chain {
		if cert == nil || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return profileError("certificate is not currently valid")
		}
	}
	return nil
}

func checkPresentedChain(raw [][]byte, usage x509.ExtKeyUsage) ([]*x509.Certificate, error) {
	if len(raw) == 0 {
		return nil, profileError("local certificate is required")
	}
	chain := make([]*x509.Certificate, 0, len(raw))
	for _, der := range raw {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
	}
	if err := pqpolicy.CheckPath(chain, usage); err != nil {
		return nil, err
	}
	if err := checkCurrentValidity(chain); err != nil {
		return nil, err
	}
	leaf := chain[0]
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return nil, profileError("invalid local leaf usage")
	}
	return chain, nil
}

func validateLocalKey(cert *tls.Certificate) error {
	if cert == nil {
		return profileError("nil local credential")
	}
	// Role-specific usage is also checked against ConnectionState before use.
	chain, err := checkPresentedChain(cert.Certificate, x509.ExtKeyUsageAny)
	if err != nil {
		return err
	}
	key, ok := cert.PrivateKey.(*mldsa.PrivateKey)
	if !ok || key == nil {
		return profileError("local private key must be native ML-DSA-65")
	}
	equal, err := cryptoutil.PublicKeyEqual(key.Public(), chain[0].PublicKey)
	if err != nil || !equal {
		return profileError("local certificate does not match private key")
	}
	cert.Leaf = chain[0]
	return nil
}
