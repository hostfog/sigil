import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { it } from 'node:test';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../interop.mjs', import.meta.url));

it('checks its own interop output', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sigil-'));
  try {
    const out = join(dir, 'node.json');
    execFileSync(process.execPath, [script, 'gen', out]);
    assert.equal(JSON.parse(readFileSync(out, 'utf8')).length, 41);
    assert.equal(execFileSync(process.execPath, [script, 'check', out], { encoding: 'utf8' }).trim(), '41/41 passed');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
