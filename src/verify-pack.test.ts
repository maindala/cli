// Vitest suite for verifyPack()'s handling of an untrusted manifest.json —
// the call site named directly in the task brief: "a sibling finding covered
// a path-traversal read in verify-pack.ts whose mismatch message also
// printed the computed digest, making it an exfiltration primitive."
// Ported from, and does not replace, scripts/verify-pack-confinement.mjs
// (which runs the same scenarios against the built dist as an independent,
// tooling-free proof — see that file for the original).
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { verifyPack } from './verify-pack.js';

function sha256(content: string): string {
  return `sha256:${crypto.createHash('sha256').update(content).digest('hex')}`;
}

function mkPackDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'verify-pack-test-'));
}

describe('verifyPack — traversal section name', () => {
  it('rejects a "../.." section name and never discloses the sentinel content or digest', async () => {
    const sentinelDir = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-pack-sentinel-'));
    const sentinelPath = path.join(sentinelDir, 'secret.txt');
    const sentinelContent = 'THIS-MUST-NEVER-BE-READ-OR-DISCLOSED';
    fs.writeFileSync(sentinelPath, sentinelContent);
    const sentinelDigest = sha256(sentinelContent);

    const pack = mkPackDir();
    const rel = path.relative(pack, sentinelPath); // e.g. ../../.../secret.txt
    fs.writeFileSync(path.join(pack, 'manifest.json'), JSON.stringify({
      sections: [{ name: rel, digest: sentinelDigest }],
    }));

    const result = await verifyPack(pack);
    const output = result.lines.join('\n');

    expect(result.ok).toBe(false);
    // The real property under test: nothing outside `pack` was ever read.
    expect(output).not.toContain(sentinelContent);
    expect(output).not.toContain(sentinelDigest.replace('sha256:', ''));
  });

  it('rejects a section name containing a path separator via assertFlatSegment, before resolveWithinRoot is ever reached', async () => {
    const pack = mkPackDir();
    fs.writeFileSync(path.join(pack, 'manifest.json'), JSON.stringify({
      sections: [{ name: 'sub/dir/report.txt', digest: sha256('x') }],
    }));
    const result = await verifyPack(pack);
    expect(result.ok).toBe(false);
    expect(result.lines.join('\n')).toMatch(/path separators are not allowed/);
  });
});

describe('verifyPack — symlink section pointing outside the pack (watch-it-fail territory)', () => {
  it('rejects a symlink section even when its target\'s digest matches exactly, and never discloses the target content or digest', async () => {
    const sentinelDir = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-pack-sentinel2-'));
    const sentinelPath = path.join(sentinelDir, 'secret.txt');
    const sentinelContent = 'THIS-MUST-NEVER-BE-READ-OR-DISCLOSED';
    fs.writeFileSync(sentinelPath, sentinelContent);
    const sentinelDigest = sha256(sentinelContent);

    const pack = mkPackDir();
    const linkPath = path.join(pack, 'linked.txt');
    fs.symlinkSync(sentinelPath, linkPath);
    fs.writeFileSync(path.join(pack, 'manifest.json'), JSON.stringify({
      sections: [{ name: 'linked.txt', digest: sentinelDigest }],
    }));

    const result = await verifyPack(pack);
    const output = result.lines.join('\n');

    // If the symlink check were absent, this section's digest WOULD match
    // (the attacker crafted it to) and the pack would wrongly verify "OK",
    // silently confirming the exact contents of an arbitrary file outside
    // the pack. The check must reject it as "not a regular file" instead.
    expect(result.ok).toBe(false);
    expect(output.toLowerCase()).toContain('symlink');
    expect(output).not.toContain(sentinelContent);
    expect(output).not.toContain(sentinelDigest.replace('sha256:', ''));
  });
});

describe('verifyPack — digest mismatch does not disclose the recomputed digest (exfiltration-primitive check)', () => {
  it('reports a mismatch on a legitimate (non-traversal) file without printing the actual digest value', async () => {
    const pack = mkPackDir();
    fs.writeFileSync(path.join(pack, 'report.txt'), 'tampered content');
    fs.writeFileSync(path.join(pack, 'manifest.json'), JSON.stringify({
      sections: [{ name: 'report.txt', digest: 'sha256:' + '0'.repeat(64) }],
    }));
    const result = await verifyPack(pack);
    const output = result.lines.join('\n');
    expect(result.ok).toBe(false);
    // The actual sha256 of 'tampered content' must not appear anywhere in
    // the output — printing it would let a crafted section.name be used to
    // confirm the exact contents of an arbitrary confined-but-untrusted file.
    const actualDigest = sha256('tampered content').replace('sha256:', '');
    expect(output).not.toContain(actualDigest);
    expect(output).not.toMatch(/expected|got /i);
  });
});

describe('verifyPack — legitimate packs still verify correctly (no regression from the guards)', () => {
  it('a well-formed single-section pack verifies ok and exits 0', async () => {
    const pack = mkPackDir();
    const content = 'legit report content';
    fs.writeFileSync(path.join(pack, 'report.txt'), content);
    fs.writeFileSync(path.join(pack, 'manifest.json'), JSON.stringify({
      sections: [{ name: 'report.txt', digest: sha256(content) }],
    }));
    const result = await verifyPack(pack);
    expect(result.ok).toBe(true);
    expect(result.exitCode).toBe(0);
  });

  it('a nested-but-flat-named legitimate file (no separators) still verifies', async () => {
    const pack = mkPackDir();
    const content = 'another legit section';
    fs.writeFileSync(path.join(pack, 'usage.json'), content);
    fs.writeFileSync(path.join(pack, 'manifest.json'), JSON.stringify({
      sections: [{ name: 'usage.json', digest: sha256(content) }],
    }));
    const result = await verifyPack(pack);
    expect(result.ok).toBe(true);
  });
});

describe('verifyPack — malformed input handled without crashing', () => {
  it('missing manifest.json → exitCode 2', async () => {
    const pack = mkPackDir();
    const result = await verifyPack(pack);
    expect(result.ok).toBe(false);
    expect(result.exitCode).toBe(2);
  });

  it('non-JSON manifest.json → exitCode 1', async () => {
    const pack = mkPackDir();
    fs.writeFileSync(path.join(pack, 'manifest.json'), 'not json{{{');
    const result = await verifyPack(pack);
    expect(result.exitCode).toBe(1);
  });

  it('manifest.json with no sections list → exitCode 1', async () => {
    const pack = mkPackDir();
    fs.writeFileSync(path.join(pack, 'manifest.json'), JSON.stringify({}));
    const result = await verifyPack(pack);
    expect(result.exitCode).toBe(1);
  });

  it('a section listed but missing on disk is reported, not thrown', async () => {
    const pack = mkPackDir();
    fs.writeFileSync(path.join(pack, 'manifest.json'), JSON.stringify({
      sections: [{ name: 'missing.txt', digest: sha256('x') }],
    }));
    const result = await verifyPack(pack);
    expect(result.ok).toBe(false);
    expect(result.lines.join('\n')).toContain('file missing');
  });
});
