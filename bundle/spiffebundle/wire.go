package spiffebundle

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/internal/pqjwk"
	"github.com/spiffe/go-spiffe/v2/pqjose"
	"github.com/spiffe/go-spiffe/v2/pqprofile"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type bundleDoc struct {
	Keys           []json.RawMessage `json:"keys"`
	SequenceNumber *uint64           `json:"spiffe_sequence,omitempty"`
	RefreshHint    *int64            `json:"spiffe_refresh_hint,omitempty"`
}

// ParseX509Only parses strict-profile X.509 trust from an authenticated bundle.
// The caller must bind trustDomain to the authenticated endpoint/provisioning
// channel; no serialized domain field can override it. Token and unknown-use
// entries are discarded, never admitted as JWT/WIT trust. Recognized classical
// X.509 authorities are rejected, not used as a fallback. Empty trust is valid.
func ParseX509Only(trustDomain spiffeid.TrustDomain, data []byte) (*Bundle, error) {
	return parseDocument(trustDomain, data, true)
}

// ReadX509Only is ParseX509Only for a reader. Callers must enforce transport and
// resource limits appropriate for their deployment.
func ReadX509Only(trustDomain spiffeid.TrustDomain, r io.Reader) (*Bundle, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, wrapSpiffebundleErr(fmt.Errorf("unable to read: %w", err))
	}
	return ParseX509Only(trustDomain, data)
}

func parseDocument(td spiffeid.TrustDomain, data []byte, onlyX509 bool) (*Bundle, error) {
	if td.IsZero() {
		return nil, wrapSpiffebundleErr(errors.New("trust domain is required"))
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, wrapSpiffebundleErr(errors.New("unable to parse JWKS: unexpected end of JSON input"))
	}
	fields, err := pqjwk.ParseObject(data)
	if err != nil {
		return nil, wrapSpiffebundleErr(fmt.Errorf("unable to parse JWKS: %w", err))
	}
	var doc bundleDoc
	if err := json.Unmarshal(fields["keys"], &doc.Keys); err != nil || doc.Keys == nil {
		return nil, wrapSpiffebundleErr(errors.New("no authorities found"))
	}
	if raw, ok := fields["spiffe_sequence"]; ok {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, wrapSpiffebundleErr(errors.New("invalid sequence number"))
		}
		if err := json.Unmarshal(raw, &doc.SequenceNumber); err != nil {
			return nil, wrapSpiffebundleErr(errors.New("invalid sequence number"))
		}
	}
	if raw, ok := fields["spiffe_refresh_hint"]; ok {
		if err := json.Unmarshal(raw, &doc.RefreshHint); err != nil || doc.RefreshHint == nil || *doc.RefreshHint < 0 || *doc.RefreshHint > math.MaxInt64/int64(time.Second) {
			return nil, wrapSpiffebundleErr(errors.New("invalid refresh hint"))
		}
	}
	bundle := New(td)
	if doc.SequenceNumber != nil {
		bundle.SetSequenceNumber(*doc.SequenceNumber)
	}
	if doc.RefreshHint != nil {
		bundle.SetRefreshHint(time.Duration(*doc.RefreshHint) * time.Second)
	}
	for i, raw := range doc.Keys {
		if err := parseEntry(bundle, raw, onlyX509); err != nil {
			return nil, wrapSpiffebundleErr(fmt.Errorf("error adding authority %d of JWKS: %w", i, err))
		}
	}
	return bundle, nil
}

func parseEntry(bundle *Bundle, raw []byte, onlyX509 bool) error {
	fields, err := pqjwk.ParseObject(raw)
	if err != nil {
		return err
	}
	var use, keyType string
	if field, ok := fields["use"]; ok {
		if err := json.Unmarshal(field, &use); err != nil {
			return errors.New("invalid key use")
		}
	}
	switch use {
	case x509SVIDUse:
		// Handled below.
	case jwtSVIDUse, witSVIDUse:
		if onlyX509 {
			// The X.509-only reader discards token entries and never admits
			// them.
			return nil
		}
		if use == witSVIDUse {
			return pqprofile.Unsupported("spiffebundle: WIT authority entry")
		}
	default:
		// SPIFFE requires ignoring unknown uses.
		return nil
	}
	if err := json.Unmarshal(fields["kty"], &keyType); err != nil || keyType == "" {
		return errors.New("key type is required")
	}
	switch keyType {
	case "AKP", "EC", "RSA", "OKP", "oct":
	default:
		return nil
	}
	if use == x509SVIDUse {
		var chain []json.RawMessage
		if field, ok := fields["x5c"]; ok {
			if err := json.Unmarshal(field, &chain); err != nil {
				return errors.New("invalid certificate array")
			}
		}
		if len(chain) == 0 {
			return nil
		} // SPIFFE X509-SVID section 6.2.
		if onlyX509 && keyType != "AKP" {
			return errors.New("qspiffe-pq-v1: classical X.509 authority is unsupported")
		}
		if keyType == "AKP" {
			cert, err := pqjwk.ParseX509Authority(raw)
			if err != nil {
				return err
			}
			bundle.AddX509Authority(cert)
			return nil
		}
		// Discard certificates after the first before passing to the legacy codec.
		first, err := json.Marshal(chain[:1])
		if err != nil {
			return err
		}
		fields["x5c"] = first
		raw, err = json.Marshal(fields)
		if err != nil {
			return err
		}
	}
	if use == jwtSVIDUse {
		if keyType != "AKP" {
			return errors.New("qspiffe-pq-v1: classical JWT authorities are unsupported")
		}
		keyID, publicKey, err := pqjose.ParsePublicJWK(raw)
		if err != nil {
			return err
		}
		return bundle.AddJWTAuthority(keyID, publicKey)
	}
	if keyType == "AKP" {
		return errors.New("qspiffe-pq-v1: AKP authorities for this use are unsupported")
	}
	var key jose.JSONWebKey
	if err := json.Unmarshal(raw, &key); err != nil {
		return err
	}
	switch use {
	case x509SVIDUse:
		if len(key.Certificates) != 1 {
			return errors.New("certificate is required")
		}
		bundle.AddX509Authority(key.Certificates[0])
	case jwtSVIDUse:
		if err := bundle.AddJWTAuthority(key.KeyID, key.Key); err != nil {
			return errors.Unwrap(err)
		}
	case witSVIDUse:
		if err := bundle.AddWITAuthority(key.KeyID, key.Key); err != nil {
			return errors.Unwrap(err)
		}
	}
	return nil
}

func (b *Bundle) marshalDocument() ([]byte, error) {
	if b == nil {
		return nil, wrapSpiffebundleErr(errors.New("nil bundle"))
	}
	b.mtx.RLock()
	defer b.mtx.RUnlock()
	if b.trustDomain.IsZero() {
		return nil, wrapSpiffebundleErr(errors.New("trust domain is required"))
	}
	doc := bundleDoc{Keys: make([]json.RawMessage, 0), SequenceNumber: b.sequenceNumber}
	if b.refreshHint != nil {
		if *b.refreshHint < 0 {
			return nil, wrapSpiffebundleErr(errors.New("invalid refresh hint"))
		}
		seconds := int64(*b.refreshHint / time.Second)
		if *b.refreshHint%time.Second != 0 {
			seconds++
		}
		if seconds > math.MaxInt64/int64(time.Second) {
			return nil, wrapSpiffebundleErr(errors.New("invalid refresh hint"))
		}
		doc.RefreshHint = &seconds
	}
	for _, cert := range b.x509Authorities {
		if cert == nil {
			return nil, wrapSpiffebundleErr(errors.New("nil authority"))
		}
		canonical, err := x509.ParseCertificate(bytes.Clone(cert.Raw))
		if err != nil {
			return nil, wrapSpiffebundleErr(errors.New("invalid authority DER"))
		}
		var encoded []byte
		if _, ok := canonical.PublicKey.(*mldsa.PublicKey); ok {
			encoded, err = pqjwk.MarshalX509Authority(canonical)
		} else {
			encoded, err = json.Marshal(jose.JSONWebKey{Key: canonical.PublicKey, Certificates: []*x509.Certificate{canonical}, Use: x509SVIDUse})
		}
		if err != nil {
			return nil, wrapSpiffebundleErr(err)
		}
		doc.Keys = append(doc.Keys, encoded)
	}
	for id, key := range b.jwtAuthorities {
		publicKey, ok := key.(*mldsa.PublicKey)
		if !ok {
			return nil, wrapSpiffebundleErr(errors.New("JWT authority is not an ML-DSA-65 public key"))
		}
		encoded, err := pqjose.MarshalPublicJWKWithUse(id, jwtSVIDUse, publicKey)
		if err != nil {
			return nil, wrapSpiffebundleErr(err)
		}
		doc.Keys = append(doc.Keys, encoded)
	}
	for id, key := range b.witAuthorities {
		encoded, err := json.Marshal(jose.JSONWebKey{Key: key, KeyID: id, Use: witSVIDUse})
		if err != nil {
			return nil, wrapSpiffebundleErr(err)
		}
		doc.Keys = append(doc.Keys, encoded)
	}
	return json.Marshal(doc)
}
