import { readFileSync, writeFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { KeySet, decrypt, encrypt, sign, verify } from './dist/index.js';

const testdata = new URL('../testdata/', import.meta.url);
const interop = JSON.parse(readFileSync(new URL('interop.json', testdata), 'utf8'));
const keys = KeySet.fromJSON(readFileSync(new URL('keys.json', testdata), 'utf8'));

function key(kid) {
  const found = keys.get(kid);
  if (!found) throw new Error(`unknown key ${kid}`);
  return found;
}

function gen(out) {
  const tokens = interop.cases.map(({ kind, alg, enc, key: kid }) => ({
    kind,
    alg,
    enc,
    key: kid,
    token: kind === 'jws'
      ? sign(interop.claims, key(kid), { alg })
      : encrypt(interop.claims, key(kid), { alg, enc }),
  }));
  writeFileSync(out, JSON.stringify(tokens, null, 2) + '\n');
}

function check(input) {
  const options = { now: 1800000000, issuer: 'sigil', audience: 'all' };
  let failed = 0;
  const entries = JSON.parse(readFileSync(input, 'utf8'));
  for (const { kind, alg, enc, key: kid, token } of entries) {
    const label = [kind, alg, enc, kid].filter(Boolean).join(' ');
    try {
      const open = kind === 'jws' ? verify : decrypt;
      const { header, claims } = open(token, key(kid), { ...options, algorithms: [alg] });
      if (header.alg !== alg || (kind === 'jwe' && header.enc !== enc)) throw new Error('header mismatch');
      if (!isDeepStrictEqual(claims, interop.claims)) throw new Error('claims mismatch');
    } catch (error) {
      failed++;
      console.error(`FAIL ${label}: ${error.message}`);
    }
  }
  console.log(`${entries.length - failed}/${entries.length} passed`);
  if (failed > 0) process.exitCode = 1;
}

const [command, file] = process.argv.slice(2);
if (command === 'gen' && file) gen(file);
else if (command === 'check' && file) check(file);
else {
  console.error('usage: node interop.mjs gen <out.json> | check <in.json>');
  process.exitCode = 2;
}
