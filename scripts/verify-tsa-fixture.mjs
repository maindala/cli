#!/usr/bin/env node
// Proves RFC 3161 timestamp verification works fully offline
// against the committed fixture (fixtures/evidence-pack-sample/) — a real
// timestamp token captured once from FreeTSA (see fixtures/README.md),
// never regenerated automatically. Also proves a malformed token is
// correctly rejected and an untimestamped pack still verifies on content
// alone. Run: node scripts/verify-tsa-fixture.mjs
import { verifyPack } from '../dist/verify-pack.js';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = path.join(__dirname, '..', 'fixtures', 'evidence-pack-sample');

let failures = 0;
function check(name, cond, detail) {
  if (cond) console.log(`  ok  ${name}`);
  else { failures++; console.log(`FAIL  ${name}${detail ? `: ${detail}` : ''}`); }
}

if (!fs.existsSync(FIXTURE_DIR)) {
  console.error(`Fixture directory not found: ${FIXTURE_DIR}`);
  process.exit(2);
}

// ── 1. The real, committed fixture verifies OK, fully offline ──────────────
const result = await verifyPack(FIXTURE_DIR);
console.log('--- fixture verification output ---');
console.log(result.lines.join('\n'));
check('committed fixture verifies as INTACT', result.ok === true);
check('committed fixture exits 0', result.exitCode === 0);
check('the real RFC 3161 timestamp is reported VALID', result.lines.some((l) => l.includes('RFC 3161 timestamp: VALID')));

// ── 2. A malformed/corrupted token must be rejected, not silently accepted ──
{
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tsa-malformed-'));
  fs.cpSync(FIXTURE_DIR, tmp, { recursive: true });
  const tsr = fs.readFileSync(path.join(tmp, 'timestamp.tsr'));
  // Flip a byte in the middle of the real token — corrupts the signature
  // without changing its length, so this exercises signature verification
  // specifically, not just "file too short to parse".
  const corrupted = Buffer.from(tsr);
  corrupted[Math.floor(corrupted.length / 2)] ^= 0xff;
  fs.writeFileSync(path.join(tmp, 'timestamp.tsr'), corrupted);

  const result2 = await verifyPack(tmp);
  console.log('\n--- corrupted-token verification output ---');
  console.log(result2.lines.join('\n'));
  check('corrupted token is reported INVALID, not VALID', result2.lines.some((l) => l.includes('RFC 3161 timestamp: INVALID')));
  check('a pack with a corrupted token is not reported INTACT', result2.ok === false);
  fs.rmSync(tmp, { recursive: true, force: true });
}

// ── 3. No timestamp.tsr at all — content-only verification still works ─────
{
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tsa-none-'));
  fs.cpSync(FIXTURE_DIR, tmp, { recursive: true });
  fs.rmSync(path.join(tmp, 'timestamp.tsr'));

  const result3 = await verifyPack(tmp);
  console.log('\n--- no-timestamp verification output ---');
  console.log(result3.lines.join('\n'));
  check('untimestamped pack still verifies as INTACT on content alone', result3.ok === true);
  check('untimestamped pack reports the self-consistency-only note', result3.lines.some((l) => l.includes('self-consistency check only')));
  fs.rmSync(tmp, { recursive: true, force: true });
}

console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'} — ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
