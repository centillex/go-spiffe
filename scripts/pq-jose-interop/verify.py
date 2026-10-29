#!/usr/bin/env python3
"""Independent RFC 9964 JOSE verifier for the interop check.

Reads a compact ML-DSA-65 JWS from stdin and a public JWKS from --jwks, then
verifies the signature with dilithium-py, a pure-Python FIPS 204
implementation. It never writes the token.
"""
import argparse
import base64
import json
import sys

from dilithium_py.ml_dsa import ML_DSA_65


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jwks", required=True)
    args = parser.parse_args()

    token = sys.stdin.read().strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise SystemExit("token is not a compact JWS")

    header = json.loads(b64decode(parts[0]))
    payload = json.loads(b64decode(parts[1]))
    if header.get("alg") != "ML-DSA-65":
        raise SystemExit("unexpected JWS algorithm")
    key_id = header.get("kid")
    if not key_id:
        raise SystemExit("token header has no kid")

    with open(args.jwks, encoding="utf-8") as f:
        jwks = json.load(f)
    matches = [k for k in jwks.get("keys", []) if k.get("kid") == key_id]
    if len(matches) != 1:
        raise SystemExit("expected exactly one matching JWK")
    jwk = matches[0]
    if jwk.get("kty") != "AKP" or jwk.get("alg") != "ML-DSA-65":
        raise SystemExit("JWK is not an ML-DSA-65 AKP key")
    if "priv" in jwk:
        raise SystemExit("public JWKS contains private material")

    verified = ML_DSA_65.verify(
        b64decode(jwk["pub"]),
        f"{parts[0]}.{parts[1]}".encode(),
        b64decode(parts[2]),
    )
    if not verified:
        raise SystemExit("signature verification failed")

    print(json.dumps({
        "algorithm": header["alg"],
        "key_id": key_id,
        "signature_verified": True,
        "subject": payload.get("sub"),
        "audience": payload.get("aud"),
        "verifier": "dilithium-py",
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
