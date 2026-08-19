// Shadow AI Discovery P1 task 10 (SAD-20) — `maindala verify-pack` gaining scan-manifest
// support. Builds a real scan.sarif + manifest.json pair via toManifest() (the exact
// function `maindala scan --format sarif` calls) rather than hand-rolling manifest.json, so
// these tests exercise the real shape, not an assumption about it. The evidence-pack path's
// own regression coverage lives in verify-pack.test.ts, untouched by this task.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { toManifest, type ScanManifest } from './scan.js';
import { verifyPack } from './verify-pack.js';

let dir: string;
beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-scan-manifest-test-')); });
afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

function writePack(manifest: ScanManifest, artifactBytes: Buffer): void {
  fs.writeFileSync(path.join(dir, manifest.artifact), artifactBytes);
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2));
}

// A real, frozen `maindala scan --format sarif --timestamp` round trip against the live
// public FreeTSA (captured 2026-08-19, src/fixtures/scan-pack-real-timestamp/) — not a
// synthetic/malformed token. This is the test the malformed-token case below cannot stand
// in for: a garbage token proves rejection works, but says nothing about whether a genuine
// token is ever accepted. It wasn't — a real bug (re-hashing an already-hashed digest before
// comparing to the token's messageImprint) made every genuine timestamp report INVALID until
// this exact fixture caught it live. See feedback_live_service_fixture_capture /
// feedback_green_tests_prove_only_what_they_exercise in project memory for why this class of
// test exists at all.
const REAL_FIXTURE_DIR = path.join(__dirname, 'fixtures', 'scan-pack-real-timestamp');

describe('verifyPack — real captured RFC 3161 round trip (regression for a re-hashing bug found live)', () => {
  it('a genuine timestamp token from a real TSA verifies as VALID, not just "not obviously broken"', async () => {
    const result = await verifyPack(REAL_FIXTURE_DIR);
    expect(result.lines.join('\n')).toContain('RFC 3161 timestamp: VALID');
    expect(result.ok).toBe(true);
    expect(result.exitCode).toBe(0);
  });

  it('the same fixture with a single tampered byte in the artifact fails digest AND timestamp, not a false pass', async () => {
    const tamperedDir = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-scan-manifest-tamper-'));
    fs.cpSync(REAL_FIXTURE_DIR, tamperedDir, { recursive: true });
    fs.appendFileSync(path.join(tamperedDir, 'scan.sarif'), '\n');
    const result = await verifyPack(tamperedDir);
    expect(result.ok).toBe(false);
    expect(result.lines.join('\n')).toContain('digest mismatch');
    fs.rmSync(tamperedDir, { recursive: true, force: true });
  });
});

describe('verifyPack — scan manifest detection (SAD-20)', () => {
  it('a real scan manifest.json is detected and verified as INTACT, not routed to the evidence-pack path', async () => {
    const artifactBytes = Buffer.from('{"sarif":"content"}');
    const manifest = toManifest(artifactBytes, 'scan.sarif', 'maindala@0.2.0');
    writePack(manifest, artifactBytes);

    const result = await verifyPack(dir);
    expect(result.ok).toBe(true);
    expect(result.lines.join('\n')).toContain('scan.sarif (sha256 matches manifest)');
    expect(result.lines.join('\n')).toContain('Result: INTACT');
  });

  it('a tampered artifact fails digest verification without disclosing the recomputed digest', async () => {
    const artifactBytes = Buffer.from('{"sarif":"content"}');
    const manifest = toManifest(artifactBytes, 'scan.sarif', 'maindala@0.2.0');
    writePack(manifest, artifactBytes);
    fs.writeFileSync(path.join(dir, 'scan.sarif'), Buffer.from('{"sarif":"TAMPERED"}'));

    const result = await verifyPack(dir);
    expect(result.ok).toBe(false);
    const joined = result.lines.join('\n');
    expect(joined).toContain('digest mismatch');
    expect(joined).not.toContain(crypto.createHash('sha256').update('{"sarif":"TAMPERED"}').digest('hex'));
  });

  it('a missing artifact file is reported clearly, exit code 2', async () => {
    const artifactBytes = Buffer.from('{"sarif":"content"}');
    const manifest = toManifest(artifactBytes, 'scan.sarif', 'maindala@0.2.0');
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2));
    // artifact file deliberately never written

    const result = await verifyPack(dir);
    expect(result.ok).toBe(false);
    expect(result.exitCode).toBe(2);
    expect(result.lines.join('\n')).toContain('scan.sarif: file missing');
  });

  it('a path-traversal artifact name in the manifest is rejected before any file access', async () => {
    const manifest: ScanManifest = {
      manifestVersion: 1, artifact: '../../../etc/passwd', digestAlgorithm: 'sha256',
      digest: 'a'.repeat(64), generatedAt: new Date().toISOString(), toolVersion: 'maindala@0.2.0', timestampToken: null,
    };
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2));

    const result = await verifyPack(dir);
    expect(result.ok).toBe(false);
    expect(result.lines.join('\n')).toContain('invalid artifact name');
  });

  it('an unsupported manifestVersion is rejected with a clear message, not a crash', async () => {
    const manifest = {
      manifestVersion: 99, artifact: 'scan.sarif', digestAlgorithm: 'sha256',
      digest: 'a'.repeat(64), generatedAt: new Date().toISOString(), toolVersion: 'maindala@0.2.0', timestampToken: null,
    };
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2));

    const result = await verifyPack(dir);
    expect(result.ok).toBe(false);
    expect(result.lines.join('\n')).toContain('Unsupported scan manifest version 99');
  });

  it('no timestampToken present: self-consistency check only, still INTACT on a matching digest', async () => {
    const artifactBytes = Buffer.from('{"sarif":"content"}');
    const manifest = toManifest(artifactBytes, 'scan.sarif', 'maindala@0.2.0');
    expect(manifest.timestampToken).toBeNull(); // the real default from toManifest()
    writePack(manifest, artifactBytes);

    const result = await verifyPack(dir);
    expect(result.ok).toBe(true);
    expect(result.lines.join('\n')).toContain('No timestampToken in manifest.json');
  });

  it('a malformed (non-DER, non-token) timestampToken fails verification cleanly rather than throwing', async () => {
    const artifactBytes = Buffer.from('{"sarif":"content"}');
    const manifest = toManifest(artifactBytes, 'scan.sarif', 'maindala@0.2.0');
    manifest.timestampToken = Buffer.from('not a real TSA token').toString('base64');
    writePack(manifest, artifactBytes);

    const result = await verifyPack(dir);
    expect(result.ok).toBe(false);
    expect(result.lines.join('\n')).toContain('RFC 3161 timestamp: INVALID');
  });

  it('the evidence-pack path (a manifest with a sections array) is still routed there, unaffected by scan-manifest support existing', async () => {
    // Minimal real evidence-pack shape — mirrors verify-pack.test.ts's own fixtures.
    const sectionContent = 'section content';
    const digest = `sha256:${crypto.createHash('sha256').update(sectionContent).digest('hex')}`;
    fs.writeFileSync(path.join(dir, 'section.json'), sectionContent);
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({ sections: [{ name: 'section.json', digest }] }));

    const result = await verifyPack(dir);
    expect(result.ok).toBe(true);
    expect(result.lines.join('\n')).toContain('Checking 1 section(s) against manifest.json');
  });
});
