// gennode writes a synthetic ML-DSA-65 node-attestation CA and node
// certificate for local x509pop attestation tests. Private keys stay in the
// caller-supplied build directory and are never copied to evidence.
package main

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func write(path, blockType string, der []byte) {
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0600); err != nil {
		panic(err)
	}
}

func main() {
	dir := flag.String("dir", "", "output directory")
	expired := flag.Bool("expired", false, "generate an already-expired node certificate")
	flag.Parse()
	if *dir == "" {
		panic("dir required")
	}
	if err := os.MkdirAll(*dir, 0700); err != nil {
		panic(err)
	}
	now := time.Now()

	caKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		panic(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "qspiffe synthetic node CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		panic(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		panic(err)
	}
	write(filepath.Join(*dir, "node-ca.pem"), "CERTIFICATE", caDER)
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		panic(err)
	}
	write(filepath.Join(*dir, "node-ca-key.pem"), "PRIVATE KEY", caKeyDER)

	nodeKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		panic(err)
	}
	nodeTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "qspiffe synthetic node"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(50 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if *expired {
		nodeTemplate.NotBefore = now.Add(-2 * time.Hour)
		nodeTemplate.NotAfter = now.Add(-time.Hour)
	}
	nodeDER, err := x509.CreateCertificate(rand.Reader, nodeTemplate, caCert, nodeKey.Public(), caKey)
	if err != nil {
		panic(err)
	}
	write(filepath.Join(*dir, "node.pem"), "CERTIFICATE", nodeDER)
	nodeKeyDER, err := x509.MarshalPKCS8PrivateKey(nodeKey)
	if err != nil {
		panic(err)
	}
	write(filepath.Join(*dir, "node-key.pem"), "PRIVATE KEY", nodeKeyDER)

	fmt.Println(filepath.Join(*dir, "node-ca.pem"))
}
