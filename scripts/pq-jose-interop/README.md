# Independent JOSE interop check

`verify.py` parses a compact ML-DSA-65 JWS and an AKP JWKS without using any
qspiffe code, then verifies the signature with
[`dilithium-py`](https://pypi.org/project/dilithium-py/), a pure-Python FIPS 204
implementation. It checks the RFC 9964 AKP `pub` encoding, the ML-DSA-65 `alg`
value, the `kid` lookup, and that the public JWKS contains no `priv` member.

```sh
python3 -m venv /tmp/pqverify
/tmp/pqverify/bin/pip install dilithium-py
PQ_JOSE_VERIFIER=/tmp/pqverify/bin/python \
  bash scripts/pq-deploy/run.sh ../docs/evidence/step6/jwt
```

The deployment script streams a freshly fetched token into the verifier and
never writes it to disk; `jwt-interop.json` records only the algorithm, key ID,
subject, audience and verification result.

This is format/cryptography interop, not SPIFFE trust admission or an
independent review of SPIRE policy.
