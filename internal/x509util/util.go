package x509util

import (
	"bytes"
	"crypto/x509"
)

// NewCertPool returns a new CertPool with the given X.509 certificates
func NewCertPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

// CopyX509Authority detaches certificate DER and reparses valid certificates.
// Invalid direct constructions retain only their detached DER; they must be
// rejected by serialization/authentication boundaries, not repaired implicitly.
func CopyX509Authority(cert *x509.Certificate) *x509.Certificate {
	if cert == nil {
		return nil
	}
	raw := bytes.Clone(cert.Raw)
	if parsed, err := x509.ParseCertificate(raw); err == nil {
		return parsed
	}
	return &x509.Certificate{Raw: raw}
}

// CertificatesEqual compares encoded certificates, including nil values.
func CertificatesEqual(a, b *x509.Certificate) bool {
	if a == nil || b == nil {
		return a == b
	}
	return bytes.Equal(a.Raw, b.Raw)
}

// CopyX509Authorities detaches the slice and each certificate's encoded material.
func CopyX509Authorities(x509Authorities []*x509.Certificate) []*x509.Certificate {
	copiedX509Authorities := make([]*x509.Certificate, len(x509Authorities))
	for i, cert := range x509Authorities {
		copiedX509Authorities[i] = CopyX509Authority(cert)
	}

	return copiedX509Authorities
}

// CertsEqual returns true if the slices of X.509 certificates are equal.
func CertsEqual(a, b []*x509.Certificate) bool {
	if len(a) != len(b) {
		return false
	}

	for i, cert := range a {
		if !CertificatesEqual(cert, b[i]) {
			return false
		}
	}

	return true
}

func RawCertsFromCerts(certs []*x509.Certificate) [][]byte {
	rawCerts := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		rawCerts = append(rawCerts, cert.Raw)
	}
	return rawCerts
}

func ConcatRawCertsFromCerts(certs []*x509.Certificate) []byte {
	var rawCerts []byte
	for _, cert := range certs {
		rawCerts = append(rawCerts, cert.Raw...)
	}
	return rawCerts
}
