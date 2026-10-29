// genweb writes a synthetic ML-DSA-65 Web PKI CA and serving certificate.
// Private keys are written only under the caller-supplied build directory.
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
	"net"
	"os"
	"path/filepath"
	"time"
)

func write(path string, blockType string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0600)
}

func main() {
	dir := flag.String("dir", "", "output directory")
	commonName := flag.String("cn", "localhost", "serving certificate common name")
	caCertPath := flag.String("ca-cert", "", "existing CA certificate (optional)")
	caKeyPath := flag.String("ca-key", "", "existing CA private key (optional)")
	flag.Parse()
	if *dir == "" {
		panic("dir required")
	}
	if err := os.MkdirAll(*dir, 0700); err != nil {
		panic(err)
	}
	now := time.Now()
	caCertFile := filepath.Join(*dir, "web-ca.pem")
	caKeyFile := filepath.Join(*dir, "web-ca-key.pem")
	if *caCertPath == "" || *caKeyPath == "" {
		caKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
		must(err)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "qspiffe synthetic Web PKI CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caKey.Public(), caKey)
		must(err)
		must(write(caCertFile, "CERTIFICATE", der))
		keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
		must(err)
		must(write(caKeyFile, "PRIVATE KEY", keyDER))
		*caCertPath = caCertFile
		*caKeyPath = caKeyFile
	} else {
		data, err := os.ReadFile(*caCertPath)
		must(err)
		// Operator-supplied local output path for a synthetic test fixture.
		must(os.WriteFile(caCertFile, data, 0600)) //nolint:gosec // local test utility, paths supplied by the operator
	}
	caPEM, err := os.ReadFile(*caCertPath)
	must(err)
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		panic("invalid CA PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	must(err)
	caKeyPEM, err := os.ReadFile(*caKeyPath)
	must(err)
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		panic("invalid CA key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	must(err)
	caKey, ok := parsed.(*mldsa.PrivateKey)
	if !ok {
		panic("CA key must be ML-DSA-65")
	}

	leafKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	must(err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: *commonName}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, leafKey.Public(), caKey)
	must(err)
	certFile := filepath.Join(*dir, "serving.pem")
	keyFile := filepath.Join(*dir, "serving-key.pem")
	must(write(certFile, "CERTIFICATE", der))
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	must(err)
	must(write(keyFile, "PRIVATE KEY", keyDER))
	body, err := os.ReadFile(certFile)
	must(err)
	if _, err := os.Stdout.Write(body); err != nil {
		panic(err)
	}
	fmt.Fprintln(os.Stderr, certFile)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
