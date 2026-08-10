#!/usr/bin/env node
// Proves verify-pack cannot read or disclose anything outside the pack
// directory, via a real traversal section, a real symlink section, and a
// real sentinel file whose digest must never appear in any output.
// Run: node scripts/verify-pack-confinement.mjs
import { verifyPack } from '../dist/verify-pack.js';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';

let failures = 0;
function check(name, cond, detail) {
  if (cond) { console.log(`  ok  ${name}`); }
  else { failures++; console.log(`FAIL  ${name}${detail ? `: ${detail}` : ''}`); }
}

const sentinelDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vp-sentinel-'));
const sentinelPath = path.join(sentinelDir, 'secret.txt');
const sentinelContent = 'THIS-MUST-NEVER-BE-READ-OR-DISCLOSED';
fs.writeFileSync(sentinelPath, sentinelContent);
const sentinelDigest = `sha256:${crypto.createHash('sha256').update(sentinelContent).digest('hex')}`;

// ── Pack 1: traversal section name ──────────────────────────────────────────
const pack1 = fs.mkdtempSync(path.join(os.tmpdir(), 'vp-pack1-'));
const rel = path.relative(pack1, sentinelPath); // e.g. ../../.../secret.txt
fs.writeFileSync(path.join(pack1, 'manifest.json'), JSON.stringify({
  sections: [{ name: rel, digest: sentinelDigest }],
}));

const result1 = await verifyPack(pack1);
const output1 = result1.lines.join('\n');
console.log('--- Pack 1 (traversal section name) output ---');
console.log(output1);
check('traversal pack is rejected (not ok)', result1.ok === false);
check('sentinel digest does not appear anywhere in output', !output1.includes(sentinelDigest.replace('sha256:', '')));
check('sentinel content does not appear in output', !output1.includes(sentinelContent));

// ── Pack 2: symlink section pointing outside the pack ───────────────────────
const pack2 = fs.mkdtempSync(path.join(os.tmpdir(), 'vp-pack2-'));
const linkPath = path.join(pack2, 'linked.txt');
fs.symlinkSync(sentinelPath, linkPath);
fs.writeFileSync(path.join(pack2, 'manifest.json'), JSON.stringify({
  sections: [{ name: 'linked.txt', digest: sentinelDigest }],
}));

const result2 = await verifyPack(pack2);
const output2 = result2.lines.join('\n');
console.log('\n--- Pack 2 (symlink section) output ---');
console.log(output2);
check('symlink pack is rejected (not ok)', result2.ok === false);
check('symlink pack output mentions symlinks are rejected', output2.toLowerCase().includes('symlink'));
check('sentinel digest does not appear anywhere in symlink-pack output', !output2.includes(sentinelDigest.replace('sha256:', '')));

// ── Legitimate pack still verifies correctly (no regression) ───────────────
const pack3 = fs.mkdtempSync(path.join(os.tmpdir(), 'vp-pack3-'));
const content3 = 'legit report content';
const digest3 = `sha256:${crypto.createHash('sha256').update(content3).digest('hex')}`;
fs.writeFileSync(path.join(pack3, 'report.txt'), content3);
fs.writeFileSync(path.join(pack3, 'manifest.json'), JSON.stringify({
  sections: [{ name: 'report.txt', digest: digest3 }],
}));
const result3 = await verifyPack(pack3);
console.log('\n--- Pack 3 (legitimate, untimestamped) output ---');
console.log(result3.lines.join('\n'));
check('legitimate pack verifies ok', result3.ok === true);
check('legitimate pack exits 0', result3.exitCode === 0);

// ── Real digest mismatch on a legitimate (non-traversal) file still reported, without disclosing the digest ──
const pack4 = fs.mkdtempSync(path.join(os.tmpdir(), 'vp-pack4-'));
fs.writeFileSync(path.join(pack4, 'report.txt'), 'tampered content');
fs.writeFileSync(path.join(pack4, 'manifest.json'), JSON.stringify({
  sections: [{ name: 'report.txt', digest: 'sha256:0000000000000000000000000000000000000000000000000000000000000000' }],
}));
const result4 = await verifyPack(pack4);
const output4 = result4.lines.join('\n');
console.log('\n--- Pack 4 (real digest mismatch) output ---');
console.log(output4);
check('mismatched pack is rejected', result4.ok === false);
check('mismatch message does not disclose the recomputed digest value', !output4.includes('expected') && !output4.includes('got '));

for (const d of [sentinelDir, pack1, pack2, pack3, pack4]) fs.rmSync(d, { recursive: true, force: true });

console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'} — ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
