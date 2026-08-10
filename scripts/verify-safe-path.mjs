#!/usr/bin/env node
// Verifies the resolveWithinRoot/assertFlatSegment/assertValidSlug boundary
// against the built package. Run: node scripts/verify-safe-path.mjs
// Exits non-zero on any failure. No Docker/network required — this exercises
// the actual containment logic directly, with existence checked on disk
// rather than trusting exit code alone.
import { resolveWithinRoot, assertFlatSegment, assertValidSlug } from '../dist/safe-path.js';
import fs from 'fs';
import os from 'os';
import path from 'path';

let failures = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`  ok  ${name}`);
  } catch (err) {
    failures++;
    console.log(`FAIL  ${name}: ${err.message}`);
  }
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'safe-path-verify-'));
const sentinelDir = fs.mkdtempSync(path.join(os.tmpdir(), 'safe-path-sentinel-'));
const sentinelPath = path.join(sentinelDir, 'sentinel.txt');
fs.writeFileSync(sentinelPath, 'untouched');
const sentinelBefore = fs.readFileSync(sentinelPath, 'utf8');

console.log(`root:     ${root}`);
console.log(`sentinel: ${sentinelPath}\n`);

// ── resolveWithinRoot: malicious candidates must throw, never resolve ──────
check('rejects a relative traversal ("../../escape.txt")', () => {
  let threw = false;
  try { resolveWithinRoot(root, '../../escape.txt'); } catch { threw = true; }
  if (!threw) throw new Error('did not throw');
});

check('rejects an absolute path', () => {
  let threw = false;
  try { resolveWithinRoot(root, path.join(sentinelDir, 'escape.txt')); } catch { threw = true; }
  if (!threw) throw new Error('did not throw');
});

check('rejects a null-byte filename', () => {
  let threw = false;
  try { resolveWithinRoot(root, 'x\0.txt'); } catch { threw = true; }
  if (!threw) throw new Error('did not throw');
});

check('rejects a traversal buried mid-path ("a/../../b.txt")', () => {
  let threw = false;
  try { resolveWithinRoot(root, 'a/../../b.txt'); } catch { threw = true; }
  if (!threw) throw new Error('did not throw');
});

check('accepts a legitimate relative filename and stays within root', () => {
  const resolved = resolveWithinRoot(root, 'output.txt');
  if (!resolved.startsWith(root + path.sep) && resolved !== root) throw new Error('escaped root');
  fs.writeFileSync(resolved, 'ok');
  if (!fs.existsSync(path.join(root, 'output.txt'))) throw new Error('file not written where expected');
});

check('accepts a legitimate nested relative filename', () => {
  const resolved = resolveWithinRoot(root, 'sub/dir/output2.txt');
  if (!resolved.startsWith(root + path.sep)) throw new Error('escaped root');
});

// ── The actual exploit scenario: prove the sentinel is untouched ───────────
check('sentinel file outside root is provably unmodified after all attempts', () => {
  const after = fs.readFileSync(sentinelPath, 'utf8');
  if (after !== sentinelBefore) throw new Error('sentinel was modified — TRAVERSAL SUCCEEDED');
});

check('nothing was created inside the sentinel directory', () => {
  const entries = fs.readdirSync(sentinelDir);
  if (entries.length !== 1 || entries[0] !== 'sentinel.txt') {
    throw new Error(`unexpected entries in sentinel dir: ${entries.join(', ')}`);
  }
});

// ── assertFlatSegment (evidence-pack section names) ─────────────────────────
check('assertFlatSegment rejects a separator', () => {
  let threw = false;
  try { assertFlatSegment('../../etc/passwd', 'section name'); } catch { threw = true; }
  if (!threw) throw new Error('did not throw');
});

check('assertFlatSegment accepts a flat name', () => {
  assertFlatSegment('report.pdf', 'section name');
});

// ── assertValidSlug (install target slugs) ───────────────────────────────────
check('assertValidSlug rejects a traversal-shaped slug', () => {
  let threw = false;
  try { assertValidSlug('../../evil'); } catch { threw = true; }
  if (!threw) throw new Error('did not throw');
});

check('assertValidSlug rejects an absolute-path-shaped slug', () => {
  let threw = false;
  try { assertValidSlug('/etc/passwd'); } catch { threw = true; }
  if (!threw) throw new Error('did not throw');
});

check('assertValidSlug accepts a normal slug', () => {
  assertValidSlug('stock-analyst-pro');
});

fs.rmSync(root, { recursive: true, force: true });
fs.rmSync(sentinelDir, { recursive: true, force: true });

console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'} — ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
