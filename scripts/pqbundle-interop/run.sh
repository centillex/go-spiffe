#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
export GOTOOLCHAIN=local
test "$(go env GOVERSION)" = 'go1.27.3'
test "$(node --version)" = 'v24.20.0'
output="${1:-.build/pqbundle-interop}"
mkdir -p "$output"
rm -f "$output/result.log"
npm --prefix scripts/pqbundle-interop ci --ignore-scripts --no-audit --no-fund > "$output/npm-ci.log" 2>&1
go run ./scripts/pqbundle-interop -emit "$output/go-public.json" > "$output/go-emit.json"
node scripts/pqbundle-interop/roundtrip.mjs "$output/go-public.json" "$output/jose-public.json" > "$output/node-result.json" 2> "$output/node-stderr.log"
go run ./scripts/pqbundle-interop -check "$output/jose-public.json" > "$output/go-check.json"
node --input-type=module - "$output" <<'JS'
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const output = process.argv[2];
const results = await Promise.all(['go-emit','node-result','go-check'].map(async name => JSON.parse(await readFile(`${output}/${name}.json`, 'utf8'))));
for (const result of results) {
  assert.equal(result.status, 'pass');
  assert.equal(result.certificate_sha256, results[0].certificate_sha256);
}
JS
printf '%s\n' 'PASS: Go -> panva/jose + Node/OpenSSL -> Go public AKP bundle encoding' > "$output/result.log"
