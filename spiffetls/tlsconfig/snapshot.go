package tlsconfig

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
)

func snapshotBytes(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i, b := range in {
		out[i] = bytes.Clone(b)
	}
	return out
}
func snapshotCertificate(in tls.Certificate) tls.Certificate {
	out := in
	out.Certificate = snapshotBytes(in.Certificate)
	out.OCSPStaple = bytes.Clone(in.OCSPStaple)
	out.SignedCertificateTimestamps = snapshotBytes(in.SignedCertificateTimestamps)
	out.SupportedSignatureAlgorithms = append([]tls.SignatureScheme(nil), in.SupportedSignatureAlgorithms...)
	out.Leaf = nil // reparse from the detached DER at the authentication boundary
	return out
}
func snapshotConfig(base *tls.Config) *tls.Config {
	if base == nil {
		return &tls.Config{MinVersion: tls.VersionTLS13}
	}
	out := base.Clone()
	out.NextProtos = append([]string(nil), base.NextProtos...)
	out.CurvePreferences = append([]tls.CurveID(nil), base.CurvePreferences...)
	out.CipherSuites = append([]uint16(nil), base.CipherSuites...)
	out.Certificates = make([]tls.Certificate, len(base.Certificates))
	for i, c := range base.Certificates {
		out.Certificates[i] = snapshotCertificate(c)
	}
	if base.RootCAs != nil {
		out.RootCAs = base.RootCAs.Clone()
	}
	if base.ClientCAs != nil {
		out.ClientCAs = base.ClientCAs.Clone()
	}
	out.EncryptedClientHelloConfigList = bytes.Clone(base.EncryptedClientHelloConfigList)
	out.EncryptedClientHelloKeys = append([]tls.EncryptedClientHelloKey(nil), base.EncryptedClientHelloKeys...)
	for i := range out.EncryptedClientHelloKeys {
		out.EncryptedClientHelloKeys[i].Config = bytes.Clone(out.EncryptedClientHelloKeys[i].Config)
		out.EncryptedClientHelloKeys[i].PrivateKey = bytes.Clone(out.EncryptedClientHelloKeys[i].PrivateKey)
	}
	return out
}
func snapshotCerts(in []*x509.Certificate) []*x509.Certificate {
	out := make([]*x509.Certificate, len(in))
	for i, c := range in {
		if c != nil {
			out[i], _ = x509.ParseCertificate(bytes.Clone(c.Raw))
		}
	}
	return out
}
func snapshotChains(in [][]*x509.Certificate) [][]*x509.Certificate {
	out := make([][]*x509.Certificate, len(in))
	for i, c := range in {
		out[i] = snapshotCerts(c)
	}
	return out
}
func snapshotState(in tls.ConnectionState) tls.ConnectionState {
	out := in
	out.PeerCertificates = snapshotCerts(in.PeerCertificates)
	out.VerifiedChains = snapshotChains(in.VerifiedChains)
	out.LocalCertificate = snapshotBytes(in.LocalCertificate)
	out.TLSUnique = bytes.Clone(in.TLSUnique)
	out.OCSPResponse = bytes.Clone(in.OCSPResponse)
	out.SignedCertificateTimestamps = snapshotBytes(in.SignedCertificateTimestamps)
	return out
}
