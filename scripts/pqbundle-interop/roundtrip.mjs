// Independently import Go's AKP JWK with panva/jose and Node WebCrypto,
// then export a fresh JWK from the certificate's independently parsed key.
// The script only handles PUBLIC inputs/outputs; it never exports a private key.
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash, X509Certificate } from 'node:crypto';
import { exportJWK, exportSPKI, importJWK, importX509 } from 'jose';

assert.equal(process.version, 'v24.20.0');
const manifest = JSON.parse(await readFile(new URL('./node_modules/jose/package.json', import.meta.url)));
assert.equal(manifest.version, '6.2.13');
const [input, output] = process.argv.slice(2);
assert.ok(input && output, 'input/output paths required');
const bundle = JSON.parse(await readFile(input, 'utf8'));
assert.equal(bundle.keys.length, 1);
const entry = bundle.keys[0];
assert.equal(entry.kty, 'AKP');
assert.equal(entry.alg, 'ML-DSA-65');
assert.equal(entry.use, 'x509-svid');
assert.equal(entry.x5c.length, 1);
assert.ok(!Object.hasOwn(entry, 'priv') && !Object.hasOwn(entry, 'kid'));

// SPIFFE's use is not WebCrypto's JWK "sig"/"enc" vocabulary. Feed the
// standardized key parameters to JOSE; independently validate the SPIFFE wrapper.
const imported = await importJWK({ kty: entry.kty, alg: entry.alg, pub: entry.pub }, entry.alg, { extractable: true });
const der = Buffer.from(entry.x5c[0], 'base64');
const cert = new X509Certificate(der);
assert.equal(cert.ca, true);
assert.equal(cert.verify(cert.publicKey), true, 'independent signature check on synthetic self-signed fixture');
const certKey = await importX509(cert.toString(), entry.alg, { extractable: true });
assert.equal(await exportSPKI(imported), await exportSPKI(certKey), 'JWK and certificate keys must match');
const exported = await exportJWK(certKey);
assert.equal(exported.kty, 'AKP');
assert.equal(exported.alg, entry.alg);
assert.equal(exported.pub, entry.pub);
assert.equal(Buffer.from(exported.pub, 'base64url').length, 1952);
assert.ok(!Object.hasOwn(exported, 'priv'));
await writeFile(output, JSON.stringify({
  keys: [{ ...exported, use: 'x509-svid', x5c: [der.toString('base64')] }],
  spiffe_sequence: bundle.spiffe_sequence,
  spiffe_refresh_hint: bundle.spiffe_refresh_hint,
}), { mode: 0o600 });
console.log(JSON.stringify({
  status: 'pass', node: process.version, openssl: process.versions.openssl,
  jose: manifest.version, algorithm: exported.alg,
  certificate_sha256: createHash('sha256').update(der).digest('hex'),
  go_jwk_import: true, certificate_key_match: true, independent_jwk_export: true,
  scope: 'Public AKP JWK/certificate encoding interoperability, not independent SPIFFE deployment or TLS interoperability',
}));
