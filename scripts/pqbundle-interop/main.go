// This validation tool emits public certificates only. Private keys remain
// ephemeral in memory. It is not an issuer or production trust provisioner.
package main

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func main() {
	emit := flag.String("emit", "", "write a synthetic public bundle")
	check := flag.String("check", "", "read an independently encoded public bundle")
	flag.Parse()
	if (*emit == "") == (*check == "") {
		panic("specify exactly one of -emit or -check")
	}
	td := spiffeid.RequireTrustDomainFromString("interop.example")
	var data []byte
	var err error
	if *emit != "" {
		key, e := mldsa.GenerateKey(mldsa.MLDSA65())
		must(e)
		now := time.Now()
		template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic interop CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, e := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		must(e)
		cert, e := x509.ParseCertificate(der)
		must(e)
		b := spiffebundle.FromX509Authorities(td, []*x509.Certificate{cert})
		b.SetSequenceNumber(4)
		b.SetRefreshHint(60 * time.Second)
		data, err = b.Marshal()
		must(err)
		must(os.WriteFile(*emit, data, 0600))
	} else {
		data, err = os.ReadFile(*check)
		must(err)
	}
	b, err := spiffebundle.ParseX509Only(td, data)
	must(err)
	sequence, sequenceOK := b.SequenceNumber()
	hint, hintOK := b.RefreshHint()
	if !sequenceOK || sequence != 4 || !hintOK || hint != 60*time.Second {
		panic("bundle metadata changed")
	}
	certs := b.X509Authorities()
	if len(certs) != 1 || len(b.JWTAuthorities()) != 0 || len(b.WITAuthorities()) != 0 {
		panic("unexpected authority set")
	}
	hash := sha256.Sum256(certs[0].Raw)
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"go_version": runtime.Version(), "certificate_sha256": hex.EncodeToString(hash[:]), "trust_domain": b.TrustDomain().String(), "authorities": len(certs), "status": "pass"}))
}
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
