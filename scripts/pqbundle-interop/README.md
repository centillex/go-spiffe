# Public AKP bundle format interoperability

Run from the module root with Go 1.27.3 and Node 24.20.0 on PATH:

```sh
bash scripts/pqbundle-interop/run.sh .build/pqbundle-interop
```

The script requires these exact runtimes, disables Go toolchain switching, and
installs panva/jose **6.2.13** using npm ci and the checked-in lockfile/integrity.
Installation scripts are disabled. Node/npm are validation dependencies only,
not SDK runtime dependencies. The Linux CI job runs this same script.

1. Native Go generates an ephemeral ML-DSA-65 CA and emits its **public** SPIFFE
   bundle through the normal public Marshal API.
2. panva/jose imports Go's RFC 9964 AKP key using Node WebCrypto. Node/OpenSSL
   independently parses the X.509 certificate and verifies this synthetic root's
   self-signature. The independently imported certificate and JWK keys must match.
3. panva/jose exports new AKP parameters from the independently parsed certificate
   key (not by copying Go's pub field). The wrapper adds SPIFFE's use and x5c.
4. Go's public ParseX509Only reads this independently encoded entry. All three
   results must agree on the certificate's SHA-256 digest.

Only public certificate/JWK material and result metadata are saved. The generated
private key remains in Go memory; no private JWK is imported or exported. Private
keys and TLS/session secrets are not artifacts. npm's exact package integrity is
recorded in package-lock.json.

This establishes bounded public-key/certificate **format** interoperability.
It does not establish a real independent SPIFFE issuer/deployment, independent
TLS interoperability, full primitive validation (step 9), operational thresholds,
FIPS certification, or independent security review. Root self-signature checking
here is an extra test, not a substitute for authentic trust provisioning.

For the initial local Linux/amd64 run, Node was installed in the ignored
`.build/interop` directory, without replacing system Node. The official archive:

- https://nodejs.org/dist/v24.20.0/node-v24.20.0-linux-x64.tar.xz
- SHA-256: `2f2c0da162318f0de47665410c7c8c2ed3d36c8f3105de4bbc61176c70a7cbf2`

The digest was checked against Node's HTTPS SHASUMS256.txt before extraction.
CI obtains the exact Node version via actions/setup-node instead.
