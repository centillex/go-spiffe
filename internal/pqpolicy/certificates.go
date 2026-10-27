package pqpolicy

import (
	"crypto/mldsa"
	"crypto/x509"
	"fmt"
)

// CheckCertificate checks algorithm admission only. Callers must separately
// verify signatures, validity, identity, usages, and authentic trust provisioning.
// The certificate must have been freshly parsed from its DER at the boundary.
func CheckCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("%s: nil certificate", ID)
	}
	key, ok := cert.PublicKey.(*mldsa.PublicKey)
	// Check size before Parameters, which panics on a zero-value native key.
	if !ok || key == nil || len(key.Bytes()) != mldsa.MLDSA65().PublicKeySize() || key.Parameters() != mldsa.MLDSA65() {
		return fmt.Errorf("%s: certificate key must be ML-DSA-65", ID)
	}
	if cert.SignatureAlgorithm != x509.MLDSA65 {
		return fmt.Errorf("%s: certificate signature must be ML-DSA-65", ID)
	}
	return nil
}

// ParseCertificates discards caller-supplied parsed fields. Authentication must
// use the signed DER, not mutable fields in exported x509.Certificate objects.
func ParseCertificates(certs []*x509.Certificate) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(certs))
	for _, cert := range certs {
		if cert == nil {
			return nil, fmt.Errorf("%s: nil certificate", ID)
		}
		parsed, err := x509.ParseCertificate(cert.Raw)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid certificate DER: %w", ID, err)
		}
		out = append(out, parsed)
	}
	return out, nil
}

// CheckPath applies policy to a path that has already passed x509 verification,
// including its anchor. It does not require an anchor self-signature check.
func CheckPath(chain []*x509.Certificate, usages ...x509.ExtKeyUsage) error {
	if len(chain) == 0 {
		return fmt.Errorf("%s: empty certification path", ID)
	}
	for i, cert := range chain {
		if err := CheckCertificate(cert); err != nil {
			return err
		}
		if i == 0 && (cert.IsCA || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 || cert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0) {
			return fmt.Errorf("%s: invalid leaf key usage", ID)
		}
		if i > 0 && (!cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0) {
			return fmt.Errorf("%s: authority must be a CA with keyCertSign", ID)
		}
		for _, usage := range usages {
			if usage == x509.ExtKeyUsageAny || len(cert.ExtKeyUsage) == 0 {
				continue
			}
			allowed := false
			for _, actual := range cert.ExtKeyUsage {
				allowed = allowed || actual == x509.ExtKeyUsageAny || actual == usage
			}
			if !allowed {
				return fmt.Errorf("%s: certificate does not permit required extended key usage", ID)
			}
		}
	}
	return nil
}
