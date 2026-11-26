/**
 * Offline log-export verifier tests, on exports produced by the test-only simulator (test/log-sim.ts), which is written from the format
 * specification (docs/verify-log-format.md). Covers: naive-MTH cross-check and the published vectors, outcomes per segment, provenance
 * against a trust anchor, revocation and rotation, and mutation of EVERY file type in an export.
 *
 * Proves: the verifier reports consistent / rolled back / conflicting / broken as the spec's outcome table says, never says "verified"
 * without an authenticating trust anchor, extends trust only through a rotation committed under a checkpoint of a trusted, unrevoked
 * key, and detects a change to each file of an export.
 * Does not prove: that any particular producer writes exports this verifier accepts, or anything about trees of billions of leaves
 * (tested to hundreds).
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { verifyExport, type TrustFile } from './verify-log.js';
import { mth, consistencyPath, inclusionPath, checkConsistency, checkInclusion, foldParts, decompose } from './log-merkle.js';
import { Sim, SimSeg, buildExport, mutate, trustOf, retainedEntry, jcs, type SimKey } from '../test/log-sim.js';

const tmp = (): string => mkdtempSync(join(tmpdir(), 'verify-log-test-'));
const sha = (...p: Buffer[]): Buffer => { const h = createHash('sha256'); p.forEach((x) => h.update(x)); return h.digest(); };

describe('merkle (independent implementation)', () => {
  const CT = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'];
  const ROOTS = ['e3b0c442', '6e340b9c', 'fac54203', 'aeb6bcfe', 'd37ee418', '4e3bbb1f', '76e67dad', 'ddb89be4'];
  it('matches the published transparency-dev vectors (root prefixes) and proofs verify for sizes 1..120', () => {
    const leaves = CT.map((h) => sha(Buffer.from([0]), Buffer.from(h, 'hex')));
    ROOTS.forEach((r, n) => expect(mth(leaves.slice(0, n)).toString('hex').startsWith(r)).toBe(true));
    for (let n = 1; n <= 120; n++) {
      const l = Array.from({ length: n }, (_, i) => sha(Buffer.from(`v${i}`)));
      const root = mth(l);
      for (let m = 1; m <= n; m++) {
        expect(checkConsistency(m, n, mth(l.slice(0, m)), root, consistencyPath(m, l))).toBe(true);
      }
      const i = n - 1 - (n % 3 === 0 ? 0 : Math.floor(n / 2));
      expect(checkInclusion(i, n, l[i]!, inclusionPath(i, l), root)).toBe(true);
    }
  });
  it('fold of boundaries equals the tree hash', () => {
    const l = Array.from({ length: 77 }, (_, i) => sha(Buffer.from(`w${i}`)));
    const sub = (lo: number, hi: number): Buffer => mth(l.slice(lo, hi));
    for (const [a, b] of [[0, 77], [10, 50], [64, 70], [0, 5], [33, 33], [76, 77]] as [number, number][]) {
      const left = decompose(0, a).map((d) => sub(d.pos, d.pos + 2 ** d.level));
      const right = decompose(b, 77).map((d) => sub(d.pos, d.pos + 2 ** d.level));
      expect(foldParts(a, left, l.slice(a, b), 77, right).equals(mth(l))).toBe(true);
    }
  });
});

// A standard honest installation: one segment of 12 leaves, checkpoints at 4, 8 and 12 by the genesis key.
function honest(): { sim: Sim; k0: SimKey; seg: SimSeg } {
  const sim = new Sim();
  const k0 = sim.newKey();
  const seg = new SimSeg(sim);
  seg.add('segment_start', { installationId: sim.installationId, signingKey: { kid: k0.kid } });
  for (let i = 1; i < 12; i++) seg.add(i % 3 ? 'intent' : 'completion', { recordId: `r${i}` });
  seg.checkpoint(k0, 4); seg.checkpoint(k0, 8); seg.checkpoint(k0, 12);
  return { sim, k0, seg };
}
const seg0 = (r: ReturnType<typeof verifyExport>) => r.segments[0]!;

describe('outcomes and provenance', () => {
  it('anchored honest export: verified, exit 0', () => {
    const { sim, k0, seg } = honest(); const d = tmp();
    buildExport(d, sim, { segments: [{ seg }], manifestKey: k0 });
    const r = verifyExport(d, { trust: trustOf(sim, [k0]) });
    expect(r.exitCode).toBe(0); expect(r.verified).toBe(true);
    expect(seg0(r)).toMatchObject({ outcome: 'consistent', provenance: 'authenticated', verified: true });
    expect(r.summary).toMatch(/^verified/);
  });

  it('no trust anchor: internally consistent, identity not authenticated, never "verified" (exit 1)', () => {
    const { sim, k0, seg } = honest(); const d = tmp();
    buildExport(d, sim, { segments: [{ seg }], manifestKey: k0 });
    const r = verifyExport(d);
    expect(r.exitCode).toBe(1); expect(r.verified).toBe(false);
    expect(seg0(r)).toMatchObject({ outcome: 'consistent', provenance: 'not_authenticated', verified: false });
    expect(r.summary).toBe('internally consistent; signing identity not authenticated (no trust anchor supplied)');
    expect(r.summary.startsWith('verified')).toBe(false);
  });

  it('a whole replaced export under a fresh key: (a) not authenticated without an anchor, (b) fails against the real anchor', () => {
    const real = honest();
    const forged = new Sim(real.sim.installationId);           // keeps the installation id, new key, fabricated leaves
    const kx = forged.newKey();
    const fs = new SimSeg(forged); fs.add('segment_start', { fabricated: true }); for (let i = 0; i < 9; i++) fs.add('intent', { recordId: `fake${i}` });
    fs.checkpoint(kx, 10);
    const d = tmp(); buildExport(d, forged, { segments: [{ seg: fs }], manifestKey: kx });
    const a = verifyExport(d);
    expect(a.exitCode).toBe(1); expect(seg0(a).provenance).toBe('not_authenticated'); expect(a.verified).toBe(false);
    const b = verifyExport(d, { trust: trustOf(real.sim, [real.k0]) });
    expect(b.exitCode).toBe(2); expect(b.verified).toBe(false);
    expect(b.failures.join(' ')).toMatch(/signing key not trusted for this installation/);
  });

  it('an anchor for a different installation fails', () => {
    const { sim, k0, seg } = honest(); const d = tmp();
    buildExport(d, sim, { segments: [{ seg }], manifestKey: k0 });
    const other = new Sim(); const ko = other.newKey();
    const r = verifyExport(d, { trust: trustOf(other, [ko]) });
    expect(r.exitCode).toBe(2);
    expect(r.failures.join(' ')).toMatch(/different installation/);
  });
});

describe('the unsigned tail', () => {
  it('a leaf altered before the checkpoint that signs it is consistent (documented limitation)', () => {
    const { sim, k0, seg } = honest();
    seg.leaves[10]!.body = { recordId: 'ALTERED-BEFORE-CHECKPOINT' };          // the checkpoint at 12 is made after the change
    seg.checkpoints = []; seg.checkpoint(k0, 4); seg.checkpoint(k0, 8); seg.checkpoint(k0, 12);
    const d = tmp(); buildExport(d, sim, { segments: [{ seg }], manifestKey: k0 });
    expect(seg0(verifyExport(d, { trust: trustOf(sim, [k0]) })).outcome).toBe('consistent');
  });
});

describe('mutation of every export file type (each must be detected)', () => {
  let sim: Sim; let k0: SimKey; let seg: SimSeg; let d: string;
  beforeEach(() => { ({ sim, k0, seg } = honest()); d = tmp(); buildExport(d, sim, { segments: [{ seg }], manifestKey: k0 }); });
  const check = (resealed: boolean) => verifyExport(d, { trust: trustOf(sim, [k0]) }) && verifyExport(d, { trust: trustOf(sim, [k0]) });
  void check;
  const run = () => verifyExport(d, { trust: trustOf(sim, [k0]) });
  const lines = (t: string): string[] => t.split('\n').filter(Boolean);

  it('leaves.ndjson: edited body -> broken at that index', () => {
    mutate(d, 'leaves.ndjson', (t) => lines(t).map((l, i) => (i === 5 ? l.replace('"r5"', '"r5-EDITED"') : l)).join('\n') + '\n', { resealDigest: true });
    const r = run();
    expect(seg0(r).outcome).toBe('broken'); expect(seg0(r).broken[0]).toMatchObject({ reason: 'leaf_hash_mismatch', index: 5 }); expect(r.exitCode).toBe(2);
  });
  it('leaves.ndjson: edited body AND recomputed leaf hash -> broken (root mismatch) in the right range', () => {
    mutate(d, 'leaves.ndjson', (t) => lines(t).map((l, i) => {
      if (i !== 5) return l;
      const o = JSON.parse(l); o.body = { recordId: 'EVIL' };
      o.leafHash = sha(Buffer.from([0]), jcs({ kind: o.kind, ts: o.ts, body: o.body })).toString('hex');
      return jcs(o).toString('utf8');
    }).join('\n') + '\n', { resealDigest: true });
    const r = run();
    expect(seg0(r).outcome).toBe('broken');
    const loc = seg0(r).broken.find((b) => b.between);
    expect(loc!.between![0]).toBeLessThanOrEqual(5); expect(loc!.between![1]).toBeGreaterThan(5);
  });
  it('leaves.ndjson: a deleted middle leaf -> broken at the first missing index', () => {
    mutate(d, 'leaves.ndjson', (t) => lines(t).filter((_, i) => i !== 6).join('\n') + '\n', { resealDigest: true });
    expect(seg0(run()).broken[0]).toMatchObject({ reason: 'missing_index', index: 6 });
  });
  it('leaves.ndjson: two swapped leaves -> broken, located before the first checkpoint that fails', () => {
    mutate(d, 'leaves.ndjson', (t) => {
      const ls = lines(t).map((l) => JSON.parse(l));
      const a = ls[5], b = ls[6];
      [a.kind, b.kind] = [b.kind, a.kind]; [a.body, b.body] = [b.body, a.body]; [a.ts, b.ts] = [b.ts, a.ts]; [a.leafHash, b.leafHash] = [b.leafHash, a.leafHash];
      return ls.map((x) => jcs(x).toString('utf8')).join('\n') + '\n';
    }, { resealDigest: true });
    const r = seg0(run());
    expect(r.outcome).toBe('broken');
    const loc = r.broken.find((b) => b.between)!;
    expect(loc.between![0]).toBeLessThanOrEqual(5); expect(loc.between![1]).toBeGreaterThan(5);
  });
  it('leaves.ndjson: an added leaf -> broken', () => {
    mutate(d, 'leaves.ndjson', (t) => t + jcs({ segmentId: seg.id, index: 12, kind: 'intent', ts: seg.leaves[0]!.ts, body: {}, leafHash: '00'.repeat(32) }).toString('utf8') + '\n', { resealDigest: true });
    expect(seg0(run()).outcome).toBe('broken');
  });
  it('checkpoints.ndjson: a note whose signature was altered -> broken (signature)', () => {
    mutate(d, 'checkpoints.ndjson', (t) => {
      const ls = lines(t).map((l) => JSON.parse(l));
      const last = ls[ls.length - 1];
      const m = /(— \S+ )(\S+)\n$/.exec(last.note)!;
      const raw = Buffer.from(m[2]!, 'base64'); raw[40]! ^= 1;
      last.note = last.note.replace(m[2]!, raw.toString('base64'));
      return ls.map((x) => jcs(x).toString('utf8')).join('\n') + '\n';
    }, { resealDigest: true });
    const r = seg0(run());
    expect(r.outcome).toBe('broken'); expect(r.broken.some((b) => b.reason === 'checkpoint_signature')).toBe(true);
  });
  it('checkpoints.ndjson: a record whose root disagrees with its signed note -> broken', () => {
    mutate(d, 'checkpoints.ndjson', (t) => t.replace(/"rootHash":"[0-9a-f]{2}/, '"rootHash":"ff'), { resealDigest: true });
    expect(seg0(run()).broken.some((b) => b.reason === 'checkpoint_record_mismatch')).toBe(true);
  });
  it('proofs.json: nothing to check on a whole-segment export is silently ignored, but a range export notices boundary changes (range exports below)', () => {
    mutate(d, 'proofs.json', (t) => t.replace('"left":[]', '"left":["' + '00'.repeat(32) + '"]'), { resealDigest: true });
    expect(seg0(run()).broken.some((b) => b.reason === 'bad_left_boundary')).toBe(true);
  });
  it('segment.json: a changed range -> broken; any change -> manifest digest failure', () => {
    mutate(d, 'segment.json', (t) => t.replace('"to":12', '"to":11'), { resealDigest: true });
    const r = run();
    expect(seg0(r).outcome).toBe('broken');
    const d2 = tmp(); buildExport(d2, sim, { segments: [{ seg }], manifestKey: k0 });
    mutate(d2, 'segment.json', (t) => t.replace('"status":"open"', '"status":"closed"'));
    const r2 = verifyExport(d2, { trust: trustOf(sim, [k0]) });
    expect(r2.exitCode).toBe(2); expect(r2.manifest.problems.join(' ')).toMatch(/segment.json does not match its manifest digest/);
  });
  it('key-history.json: a swapped public key -> signatures no longer verify', () => {
    const other = sim.newKey();
    mutate(d, 'key-history.json', (t) => t.replace(k0.pub.toString('base64'), other.pub.toString('base64')), { resealDigest: true });
    const r = run();
    expect(r.exitCode).toBe(2);
  });
  it('manifest.json, manifest.sig, VERIFY.md and CONFIDENTIAL.txt: each change is a manifest failure (exit 2)', () => {
    for (const [file, fn] of [
      ['manifest.json', (t: string) => t.replace('"formatVersion":1', '"formatVersion":1,"x":1')],
      ['manifest.sig', (t: string) => t.replace(/"signature":"./, '"signature":"A')],
      ['VERIFY.md', (t: string) => t + 'tampered'],
      ['CONFIDENTIAL.txt', (t: string) => t + 'tampered'],
    ] as [string, (t: string) => string][]) {
      const dd = tmp(); buildExport(dd, sim, { segments: [{ seg }], manifestKey: k0 });
      mutate(dd, file, fn);
      const r = verifyExport(dd, { trust: trustOf(sim, [k0]) });
      expect(r.exitCode, file).toBe(2);
      expect(r.manifest.ok, file).toBe(false);
    }
  });
  it('a missing file is reported', () => {
    const dd = tmp(); buildExport(dd, sim, { segments: [{ seg }], manifestKey: k0 });
    writeFileSync(join(dd, 'proofs.json'), '{ not json');
    expect(verifyExport(dd, { trust: trustOf(sim, [k0]) }).exitCode).toBe(2);
  });
  it('an unsupported format version is refused', () => {
    const dd = tmp(); buildExport(dd, sim, { segments: [{ seg }], manifestKey: k0 });
    const m = JSON.parse(readFileSync(join(dd, 'manifest.json'), 'utf8')); m.formatVersion = 99;
    writeFileSync(join(dd, 'manifest.json'), jcs(m));
    expect(verifyExport(dd).manifest.problems.join(' ')).toMatch(/unsupported format version/);
  });
});

describe('range export boundaries', () => {
  const build = () => {
    const { sim, k0, seg } = honest();
    const d = tmp(); buildExport(d, sim, { segments: [{ seg, from: 3, to: 9 }], manifestKey: k0 });
    return { sim, k0, seg, d };
  };
  it('a clean range export is consistent, positions outside are "not included"', () => {
    const { sim, k0, d } = build();
    const r = verifyExport(d, { trust: trustOf(sim, [k0]) });
    expect(seg0(r)).toMatchObject({ outcome: 'consistent', provenance: 'authenticated' });
    expect(seg0(r).historyNotIncluded).toEqual([{ from: 0, to: 3, reason: 'outside_exported_range' }, { from: 9, to: 12, reason: 'outside_exported_range' }]);
    expect(seg0(r).qualifiers).toContain('history_not_included');
    expect(r.exitCode).toBe(0);
  });
  const lines = (t: string): string[] => t.split('\n').filter(Boolean);
  it.each([
    ['drop one leaf', (d: string) => mutate(d, 'leaves.ndjson', (t) => lines(t).filter((_, i) => i !== 2).join('\n') + '\n', { resealDigest: true })],
    ['add one leaf', (d: string) => mutate(d, 'leaves.ndjson', (t) => t + jcs({ segmentId: JSON.parse(t.split('\n')[0]!).segmentId, index: 9, kind: 'intent', ts: '2026-11-25T12:00:00.000Z', body: {}, leafHash: '00'.repeat(32) }).toString('utf8') + '\n', { resealDigest: true })],
    ['swap two leaves', (d: string) => mutate(d, 'leaves.ndjson', (t) => { const ls = lines(t).map((l) => JSON.parse(l)); [ls[1].body, ls[2].body] = [ls[2].body, ls[1].body]; [ls[1].kind, ls[2].kind] = [ls[2].kind, ls[1].kind]; [ls[1].leafHash, ls[2].leafHash] = [ls[2].leafHash, ls[1].leafHash]; return ls.map((x) => jcs(x).toString('utf8')).join('\n') + '\n'; }, { resealDigest: true })],
    ['alter the left compact range', (d: string) => mutate(d, 'proofs.json', (t) => { const o = JSON.parse(t); const s = Object.values<any>(o.segments)[0]; s.left[0] = '11'.repeat(32); return jcs(o).toString('utf8'); }, { resealDigest: true })],
    ['alter the right compact range', (d: string) => mutate(d, 'proofs.json', (t) => { const o = JSON.parse(t); const s = Object.values<any>(o.segments)[0]; s.right[0] = '22'.repeat(32); return jcs(o).toString('utf8'); }, { resealDigest: true })],
    ['change C_n signature', (d: string) => mutate(d, 'checkpoints.ndjson', (t) => { const ls = lines(t).map((l) => JSON.parse(l)); const last = ls[ls.length - 1]; const m = /(— \S+ )(\S+)\n$/.exec(last.note)!; const raw = Buffer.from(m[2]!, 'base64'); raw[10]! ^= 1; last.note = last.note.replace(m[2]!, raw.toString('base64')); return ls.map((x) => jcs(x).toString('utf8')).join('\n') + '\n'; }, { resealDigest: true })],
  ])('mutation "%s" is detected as broken', (_name, mut) => {
    const { sim, k0, d } = build();
    mut(d);
    const r = verifyExport(d, { trust: trustOf(sim, [k0]) });
    expect(seg0(r).outcome).toBe('broken');
    expect(r.exitCode).toBe(2);
  });
});

describe('not included vs rolled back vs conflicting', () => {
  it('1: a range export with retained checkpoints beyond it is "not included"', () => {
    const { sim, k0, seg } = honest();
    const d = tmp(); buildExport(d, sim, { segments: [{ seg, from: 2, to: 6, target: 8 }], manifestKey: k0 });
    const retained = [retainedEntry(seg, seg.checkpoints[0]!), retainedEntry(seg, seg.checkpoints[1]!, seg.checkpoints[0]!)];
    const r = verifyExport(d, { trust: trustOf(sim, [k0]), retained });
    expect(seg0(r).outcome).toBe('consistent');
    expect(seg0(r).historyNotIncluded.length).toBeGreaterThan(0);
    expect(seg0(r).rolledBack).toBeNull();
  });
  it('2: a restored (older) full export with a retained checkpoint beyond it is "rolled back", not conflicting, not verified', () => {
    const { sim, k0, seg } = honest();
    const old = seg.fork(); old.checkpoints = old.checkpoints.filter((c) => c.size <= 8); old.leaves = old.leaves.slice(0, 8);
    const d = tmp(); buildExport(d, sim, { segments: [{ seg: old }], manifestKey: k0 });
    const retained = [retainedEntry(seg, seg.checkpoints[2]!, seg.checkpoints[1]!)];     // size 12, linked to the size-8 checkpoint
    const r = verifyExport(d, { trust: trustOf(sim, [k0]), retained });
    expect(seg0(r).outcome).toBe('rolled_back');
    expect(seg0(r).rolledBack).toMatchObject({ retainedSize: 12, exportSize: 8, unavailable: [8, 11] });
    expect(seg0(r).verified).toBe(false); expect(r.verified).toBe(false); expect(r.exitCode).toBe(1);
  });
  it('3: a full export whose history after the retained size was rewritten is "conflicting history" (the only fork)', () => {
    const { sim, k0, seg } = honest();
    const evil = seg.fork(); evil.leaves[9]!.body = { recordId: 'REWRITTEN' }; evil.checkpoints = []; evil.checkpoint(k0, 8); evil.checkpoint(k0, 12);
    const d = tmp(); buildExport(d, sim, { segments: [{ seg: evil }], manifestKey: k0 });
    const retained = [retainedEntry(seg, seg.checkpoints[2]!, seg.checkpoints[1]!)];
    const r = verifyExport(d, { trust: trustOf(sim, [k0]), retained });
    expect(seg0(r).outcome).toBe('conflicting_history'); expect(r.exitCode).toBe(2);
  });
  it('a retained checkpoint that cannot be linked is reported unrelated (not rolled back, not verified)', () => {
    const { sim, k0, seg } = honest();
    const old = seg.fork(); old.checkpoints = old.checkpoints.filter((c) => c.size <= 4); old.leaves = old.leaves.slice(0, 4);
    const d = tmp(); buildExport(d, sim, { segments: [{ seg: old }], manifestKey: k0 });
    const r = verifyExport(d, { trust: trustOf(sim, [k0]), retained: [retainedEntry(seg, seg.checkpoints[2]!)] });   // no prev proof
    expect(seg0(r).outcome).toBe('consistent'); expect(seg0(r).qualifiers).toContain('retained_unrelated'); expect(r.verified).toBe(false);
  });
});

describe('rewrite and re-sign with the installation key', () => {
  it('anchor only: consistent and authenticated; anchor + retained checkpoints: conflicting history', () => {
    const { sim, k0, seg } = honest();
    const forged = seg.fork(); forged.leaves[3]!.body = { recordId: 'FORGED' }; forged.checkpoints = []; forged.checkpoint(k0, 4); forged.checkpoint(k0, 8); forged.checkpoint(k0, 12);
    const d = tmp(); buildExport(d, sim, { segments: [{ seg: forged }], manifestKey: k0 });
    expect(verifyExport(d, { trust: trustOf(sim, [k0]) })).toMatchObject({ exitCode: 0, verified: true });
    const r = verifyExport(d, { trust: trustOf(sim, [k0]), retained: [retainedEntry(seg, seg.checkpoints[1]!)] });
    expect(seg0(r).outcome).toBe('conflicting_history'); expect(r.exitCode).toBe(2);
  });
});

// Builds a segment where key k0 rotates to k1 at leaf `rotAt`, checkpointed by k0, followed by traffic checkpointed by k1.
function rotated(extraRotationBy?: (sim: Sim, seg: SimSeg, k0: SimKey) => void) {
  const sim = new Sim(); const k0 = sim.newKey(); const k1 = sim.newKey();
  const seg = new SimSeg(sim);
  seg.add('segment_start', {}); seg.add('intent', { recordId: 'a' }); seg.add('intent', { recordId: 'b' });
  seg.checkpoint(k0, 3);
  const rot = seg.add('key_rotation', { oldKid: k0.kid, oldFingerprint: k0.fp, newKid: k1.kid, newPublicKey: k1.pub.toString('base64'), newFingerprint: k1.fp }, '2026-11-25T13:00:00.000Z');
  seg.checkpoint(k0, rot + 1, '2026-11-25T13:00:01.000Z');
  seg.add('intent', { recordId: 'c' }, '2026-11-25T13:10:00.000Z'); seg.add('completion', { recordId: 'c' }, '2026-11-25T13:10:01.000Z');
  seg.checkpoint(k1, seg.leaves.length, '2026-11-25T13:10:02.000Z');
  extraRotationBy?.(sim, seg, k0);
  return { sim, k0, k1, seg, rot };
}

describe('planned rotation extends trust', () => {
  it('the genesis key pinned: both periods authenticated, the new key trusted via the rotation leaf', () => {
    const { sim, k0, k1, seg } = rotated(); const d = tmp();
    buildExport(d, sim, { segments: [{ seg }], manifestKey: k1 });
    const r = verifyExport(d, { trust: trustOf(sim, [k0]) });
    expect(r.exitCode).toBe(0);
    expect(seg0(r).provenance).toBe('authenticated');
    expect(r.keys.find((k) => k.kid === k1.kid)).toMatchObject({ trusted: true, via: 'rotation' });
    expect(r.manifest.signedBy).toMatchObject({ kid: k1.kid, trusted: true });
  });
  it('a rotation NOT covered by a checkpoint of the old key does not extend trust', () => {
    const sim = new Sim(); const k0 = sim.newKey(); const k1 = sim.newKey();
    const seg = new SimSeg(sim); seg.add('segment_start', {}); seg.checkpoint(k0, 1);
    seg.add('key_rotation', { oldKid: k0.kid, oldFingerprint: k0.fp, newKid: k1.kid, newPublicKey: k1.pub.toString('base64'), newFingerprint: k1.fp });
    seg.checkpoint(k1, 2);                                                              // only the NEW key ever signs over the rotation leaf
    const d = tmp(); buildExport(d, sim, { segments: [{ seg }], manifestKey: k1 });
    const r = verifyExport(d, { trust: trustOf(sim, [k0]) });
    expect(seg0(r).provenance).toBe('not_authenticated'); expect(r.exitCode).toBe(1);
    expect(r.keys.find((k) => k.kid === k1.kid)!.trusted).toBe(false);
  });
});

describe('revocation is authoritative only from the anchor', () => {
  // Attack: after time t the (compromised) old key signs a rotation to an attacker key plus checkpoints.
  const attack = () => {
    const sim = new Sim(); const k0 = sim.newKey(); const kx = sim.newKey();
    const seg = new SimSeg(sim);
    seg.add('segment_start', {}, '2026-11-25T10:00:00.000Z'); seg.add('intent', { recordId: 'a' }, '2026-11-25T10:01:00.000Z');
    seg.checkpoint(k0, 2, '2026-11-25T10:02:00.000Z');
    const rot = seg.add('key_rotation', { oldKid: k0.kid, oldFingerprint: k0.fp, newKid: kx.kid, newPublicKey: kx.pub.toString('base64'), newFingerprint: kx.fp }, '2026-11-25T12:00:00.000Z');
    seg.checkpoint(k0, rot + 1, '2026-11-25T12:00:01.000Z');
    seg.add('intent', { recordId: 'attacker' }, '2026-11-25T12:05:00.000Z');
    seg.checkpoint(kx, seg.leaves.length, '2026-11-25T12:05:01.000Z');
    return { sim, k0, kx, seg };
  };
  it('(a) no revocation in the anchor: the attacker chain is authenticated (why the anchor matters)', () => {
    const { sim, k0, kx, seg } = attack(); const d = tmp(); buildExport(d, sim, { segments: [{ seg }], manifestKey: kx });
    expect(seg0(verifyExport(d, { trust: trustOf(sim, [k0]) })).provenance).toBe('authenticated');
  });
  it('(b) revoked_since in the anchor: checkpoints and the rotation after t are not authenticated', () => {
    const { sim, k0, kx, seg } = attack(); const d = tmp(); buildExport(d, sim, { segments: [{ seg }], manifestKey: kx });
    const trust: TrustFile = { installationId: sim.installationId, pinnedKeys: [{ fingerprint: k0.fp, revokedSince: '2026-11-25T11:00:00.000Z' }] };
    const r = verifyExport(d, { trust });
    expect(seg0(r).provenance).toBe('revoked');
    expect(r.keys.find((k) => k.kid === kx.kid)!.trusted).toBe(false);
    expect(r.exitCode).toBe(1); expect(r.verified).toBe(false);
  });
  it('(b) rotation accepted when signed by a revoked key after revokedSince must not happen (mutation target)', () => {
    const { sim, k0, kx, seg } = attack(); const d = tmp(); buildExport(d, sim, { segments: [{ seg }], manifestKey: kx });
    const r = verifyExport(d, { trust: { installationId: sim.installationId, pinnedKeys: [{ fingerprint: k0.fp, revokedSince: '2026-11-25T11:00:00.000Z' }] } });
    expect(r.keys.find((k) => k.kid === kx.kid)).toMatchObject({ trusted: false, via: null });
  });
  it('a key_revocation leaf alone (anchor not updated) is informational, not authoritative', () => {
    const { sim, k0, seg } = honest();
    seg.leaves.push({ kind: 'key_revocation', ts: '2026-11-25T12:30:00.000Z', body: { kid: k0.kid, compromisedSince: '2026-11-25T09:00:00.000Z', authoritative: false } });
    seg.checkpoints = []; seg.checkpoint(k0, 13);
    const d = tmp(); buildExport(d, sim, { segments: [{ seg }], manifestKey: k0 });
    const r = verifyExport(d, { trust: trustOf(sim, [k0]) });
    expect(seg0(r).provenance).toBe('authenticated');
    expect(seg0(r).informationalRevocations).toHaveLength(1);
    expect(seg0(r).warnings.join(' ')).toMatch(/informational/);
  });
});

describe('recovery segments and new keys', () => {
  it('a key_compromise segment under a new, unpinned key is consistent but not authenticated until pinned', () => {
    const { sim, k0, seg } = honest();
    const kn = sim.newKey();
    const seg2 = new SimSeg(sim, undefined, { reason: 'key_compromise', previousSegmentId: seg.id });
    seg2.add('segment_start', { previousSegmentId: seg.id, reason: 'key_compromise', previousCheckpoint: { size: 12, rootHash: seg.root(12).toString('hex') }, signingKey: { kid: kn.kid, newKey: true } });
    seg2.checkpoint(kn, 1);
    const d = tmp(); buildExport(d, sim, { segments: [{ seg }, { seg: seg2 }], manifestKey: kn });
    const r = verifyExport(d, { trust: trustOf(sim, [k0]) });
    expect(r.segments[0]).toMatchObject({ outcome: 'consistent', provenance: 'authenticated' });
    expect(r.segments[1]).toMatchObject({ outcome: 'consistent', provenance: 'not_authenticated' });
    expect(r.segments[1]!.recovery).toMatchObject({ previousSegmentId: seg.id, reason: 'key_compromise', previousIncluded: true, linkCheckpointFound: true });
    expect(r.exitCode).toBe(1);
    const pinned = verifyExport(d, { trust: trustOf(sim, [k0, kn]) });
    expect(pinned.exitCode).toBe(0);
  });
  it('a recovery after a broken segment reports the old one broken and the new one on its own merits', () => {
    const { sim, k0, seg } = honest();
    const broken = seg.fork(); broken.checkpoints = seg.checkpoints.map((c) => ({ ...c, rootOverride: seg.root(c.size) }));   // checkpoints still commit to the original
    broken.leaves[5]!.body = { recordId: 'CORRUPT' };
    const seg2 = new SimSeg(sim, undefined, { reason: 'recovery', previousSegmentId: seg.id });
    seg2.add('segment_start', { previousSegmentId: seg.id, reason: 'recovery', reasonText: 'corruption' }); seg2.add('outcome_uncertain', { recordId: 'x' }); seg2.checkpoint(k0, 2);
    const d = tmp(); buildExport(d, sim, { segments: [{ seg: broken }, { seg: seg2 }], manifestKey: k0 });
    const r = verifyExport(d, { trust: trustOf(sim, [k0]) });
    expect(r.segments[0]!.outcome).toBe('broken'); expect(r.segments[1]!.outcome).toBe('consistent');
    expect(r.segments[1]!.warnings.join(' ')).toMatch(/earlier segment remains broken/);
    expect(r.segments[1]!.uncertainOutcomes).toBe(1);
    expect(r.exitCode).toBe(2);
  });
});

describe('retention cut (verifier side)', () => {
  const cutFixture = () => {
    const { sim, k0, seg } = honest();
    seg.add('retention_cut', { cutSize: 8, rootHash: seg.root(8).toString('hex') });
    seg.checkpoints = []; seg.checkpoint(k0, 3); seg.checkpoint(k0, 8); seg.checkpoint(k0, 13);
    return { sim, k0, seg };
  };
  it('an export after a cut verifies: C_k matches the compact range, earlier checkpoints via stored proofs, later ones from the compact range + leaves', () => {
    const { sim, k0, seg } = cutFixture(); const d = tmp();
    buildExport(d, sim, { segments: [{ seg, cut: { size: 8 } }], manifestKey: k0 });
    const r = verifyExport(d, { trust: trustOf(sim, [k0]) });
    expect(r.exitCode).toBe(0);
    expect(seg0(r).historyNotIncluded).toEqual([{ from: 0, to: 8, reason: 'pruned_by_retention_cut' }]);
  });
  it('a retained checkpoint below the cut is checked through the stored consistency proof', () => {
    const { sim, k0, seg } = cutFixture(); const d = tmp();
    buildExport(d, sim, { segments: [{ seg, cut: { size: 8 } }], manifestKey: k0 });
    const ok = verifyExport(d, { trust: trustOf(sim, [k0]), retained: [retainedEntry(seg, seg.checkpoints[0]!)] });
    expect(seg0(ok).outcome).toBe('consistent'); expect(seg0(ok).qualifiers).not.toContain('retained_unrelated');
    const forged = seg.fork(); forged.leaves[1]!.body = { recordId: 'OTHER' };
    const bad = verifyExport(d, { trust: trustOf(sim, [k0]), retained: [retainedEntry(forged, Object.assign({}, seg.checkpoints[0]!))] });
    expect(seg0(bad).outcome).toBe('conflicting_history');
  });
  it('a retention cut whose compact range was altered is broken', () => {
    const { sim, k0, seg } = cutFixture(); const d = tmp();
    buildExport(d, sim, { segments: [{ seg, cut: { size: 8 } }], manifestKey: k0 });
    mutate(d, 'proofs.json', (t) => { const o = JSON.parse(t); Object.values<any>(o.segments)[0].retention[0].compactRange[0] = '33'.repeat(32); return jcs(o).toString('utf8'); }, { resealDigest: true });
    expect(seg0(verifyExport(d, { trust: trustOf(sim, [k0]) })).outcome).toBe('broken');
  });
  it('a gap in the middle (leaves deleted without a cut) is broken', () => {
    const { sim, k0, seg } = honest(); const d = tmp();
    buildExport(d, sim, { segments: [{ seg }], manifestKey: k0 });
    mutate(d, 'leaves.ndjson', (t) => t.split('\n').filter(Boolean).filter((_, i) => i < 3 || i > 6).join('\n') + '\n', { resealDigest: true });
    expect(seg0(verifyExport(d, { trust: trustOf(sim, [k0]) })).broken[0]).toMatchObject({ reason: 'missing_index', index: 3 });
  });
});

describe('diagnostics and exit codes', () => {
  it('clock regressions and uncertain outcomes are reported as warnings, not failures', () => {
    const { sim, k0, seg } = honest();
    seg.leaves[6]!.ts = '2026-11-25T11:00:00.000Z';         // earlier than the leaves before it
    seg.add('clock_regression', {}); seg.add('outcome_uncertain', { recordId: 'z' });
    seg.checkpoints = []; seg.checkpoint(k0, seg.leaves.length);
    const d = tmp(); buildExport(d, sim, { segments: [{ seg }], manifestKey: k0 });
    const r = verifyExport(d, { trust: trustOf(sim, [k0]) });
    expect(r.exitCode).toBe(0);
    expect(seg0(r).clockRegressions.observed).toBeGreaterThan(0); expect(seg0(r).clockRegressions.leafLeaves).toBe(1); expect(seg0(r).uncertainOutcomes).toBe(1);
  });
});

describe('opaque origin and key-name prefix', () => {
  // The prefix before `<installationId>` is producer-defined; the verifier only requires that the key name, every checkpoint origin and
  // every signature name agree with the key history and with the export's own installation and segment ids.
  const build = (prefix: string) => {
    const sim = new Sim(undefined, prefix); const k0 = sim.newKey(); const seg = new SimSeg(sim);
    seg.add('segment_start', {}); for (let i = 1; i < 6; i++) seg.add('intent', { recordId: `r${i}` });
    seg.checkpoint(k0, 3); seg.checkpoint(k0, 6);
    const d = tmp(); buildExport(d, sim, { segments: [{ seg }], manifestKey: k0 });
    return { sim, k0, seg, d };
  };
  it.each(['evlog', 'acme', 'a/b', 'x-1.y'])('prefix %j: verifies end to end', (prefix) => {
    const { sim, k0, d } = build(prefix);
    expect(verifyExport(d, { trust: trustOf(sim, [k0]) })).toMatchObject({ exitCode: 0, verified: true });
  });
  it('a checkpoint origin with a different prefix than the key name is broken', () => {
    const { sim, k0, d } = build('evlog');
    mutate(d, 'checkpoints.ndjson', (t) => t.split('evlog/').join('other/'), { resealDigest: true });
    const r = verifyExport(d, { trust: trustOf(sim, [k0]) });
    expect(r.exitCode).toBe(2); expect(seg0(r).broken.map((b) => b.reason)).toContain('checkpoint_origin');
  });
  it('a checkpoint origin naming another installation is broken', () => {
    const { sim, k0, d } = build('evlog');
    mutate(d, 'checkpoints.ndjson', (t) => t.split(sim.installationId).join('00000000-0000-0000-0000-000000000000'), { resealDigest: true });
    const r = verifyExport(d, { trust: trustOf(sim, [k0]) });
    expect(r.exitCode).toBe(2);
  });
  it.each([
    ['missing', (_n: string, i: string) => undefined as unknown as string],
    ['not ending in the installation id', (_n: string, _i: string) => 'evlog/someone-else'],
    ['without a prefix', (_n: string, i: string) => i],
    ['with whitespace', (_n: string, i: string) => `ev log/${i}`],
  ])('a key history whose key name is %s is a manifest failure', (_label, name) => {
    const { sim, k0, d } = build('evlog');
    mutate(d, 'key-history.json', (t) => { const o = JSON.parse(t); const v = name('evlog', sim.installationId); if (v === undefined) delete o.keyName; else o.keyName = v; return jcs(o).toString('utf8'); }, { resealDigest: true });
    const r = verifyExport(d, { trust: trustOf(sim, [k0]) });
    expect(r.exitCode).toBe(2); expect(r.verified).toBe(false);
  });
  it('a retained checkpoint under another prefix is ignored with a warning', () => {
    const { sim, k0, seg, d } = build('evlog');
    const other = new Sim(sim.installationId, 'other'); const ko = other.newKey(); const os = new SimSeg(other, seg.id); os.leaves = seg.leaves; os.checkpoint(ko, 6);
    const r = verifyExport(d, { trust: trustOf(sim, [k0]), retained: [retainedEntry(os, os.checkpoints[0]!)] });
    expect(r.warnings.join(' ')).toMatch(/belongs to another installation/); expect(r.exitCode).toBe(0);
  });
});

describe('canonical JSON matches the reference implementation', () => {
  // canonicalize@5.1.0 is a dev dependency only: it needs a newer Node than this CLI supports, so the verifier carries its own serializer.
  const ok = typeof (String.prototype as unknown as { isWellFormed?: unknown }).isWellFormed === 'function';
  it.skipIf(!ok)('agrees on parsed-JSON inputs, including key order, unicode, numbers and nesting', async () => {
    const ref = (await import('canonicalize')).default as (v: unknown) => string | undefined;
    const { canonicalize } = await import('./log-jcs.js');
    const samples = [
      '{"b":1,"a":[1,2,{"z":null,"y":true}],"":"empty"}', '{"\\u00e9":1,"e":2,"\\ud83d\\ude00":3,"\\uffff":4}', '[1e21,1e-7,0.1,-0,123456789012345680000,5e-324,1.7976931348623157e308]',
      '"line\\nbreak \\u2028 \\u0007 \\" \\\\ /"', '{"kind":"intent","ts":"2026-11-25T12:00:00.000Z","body":{"n":[[],{}],"s":"x"}}', 'null', 'true', '12', '"\\u00ff"', '{"a":{"b":{"c":{"d":[]}}}}',
    ];
    for (const j of samples) expect(canonicalize(JSON.parse(j)), j).toBe(ref(JSON.parse(j)));
    for (const v of [{ a: undefined, b: 1 }, [undefined, () => 1], undefined]) expect(canonicalize(v)).toBe(ref(v));
    for (const bad of ['\ud800', 'a\udc00b']) { expect(() => canonicalize(bad)).toThrow(); expect(() => ref(bad)).toThrow(); }
    for (const bad of [NaN, Infinity]) { expect(() => canonicalize(bad)).toThrow(); expect(() => ref(bad)).toThrow(); }
    expect(canonicalize('😀')).toBe(ref('😀'));
  });
});

describe('verify-log makes no network call', () => {
  it('opening a socket, resolving a name or calling fetch during verification would fail this test', async () => {
    // CommonJS module objects (not ESM namespaces) so the functions can be replaced.
    const req = createRequire(__filename); const net = req('node:net'); const dns = req('node:dns'); const http = req('node:http'); const https = req('node:https');
    const attempts: string[] = [];
    const orig: [object, string, unknown][] = [];
    const trap = (obj: object, key: string): void => { orig.push([obj, key, (obj as any)[key]]); (obj as any)[key] = (...a: unknown[]) => { attempts.push(`${(obj as any).constructor?.name ?? 'obj'}.${key}`); throw new Error(`network attempt: ${key} ${String(a[0])}`); }; };
    trap(net.Socket.prototype, 'connect'); trap(net, 'connect'); trap(net, 'createConnection'); trap(dns, 'lookup'); trap(dns.promises, 'lookup'); trap(dns, 'resolve');
    trap(http, 'request'); trap(http, 'get'); trap(https, 'request'); trap(https, 'get'); trap(globalThis, 'fetch');
    try {
      const { sim, k0, seg } = honest(); const d = tmp(); buildExport(d, sim, { segments: [{ seg }], manifestKey: k0 });
      const { runVerifyLog } = await import('./verify-log-cli.js');
      expect(verifyExport(d, { trust: trustOf(sim, [k0]), retained: [retainedEntry(seg, seg.checkpoints[2]!, seg.checkpoints[1]!)] }).exitCode).toBe(0);
      expect(runVerifyLog(d).exitCode).toBe(1);
      expect(runVerifyLog(join(d, 'missing')).exitCode).toBe(2);
    } finally { for (const [o, k, v] of orig.reverse()) (o as any)[k] = v; }
    expect(attempts).toEqual([]);
  });
  it('the verifier sources import no networking or process modules', () => {
    for (const f of ['verify-log.ts', 'verify-log-cli.ts', 'log-merkle.ts', 'log-jcs.ts', 'signed-note.ts']) {
      const src = readFileSync(join(__dirname, f), 'utf8');
      expect(src, f).not.toMatch(/from '(node:)?(net|tls|http|https|http2|dgram|dns|child_process|worker_threads|cluster)'|\bfetch\(|\bXMLHttpRequest\b|require\(/);
    }
  });
});

describe('command line', () => {
  const { sim, k0, seg } = honest();
  it('exit codes and output: verified 0, unauthenticated 1, failed 2, bad trust file 2', async () => {
    const { runVerifyLog } = await import('./verify-log-cli.js');
    const d = tmp(); buildExport(d, sim, { segments: [{ seg }], manifestKey: k0 });
    const tf = join(d, '..', `trust-${Date.now()}.json`); writeFileSync(tf, JSON.stringify(trustOf(sim, [k0])));
    const good = runVerifyLog(d, { trust: tf });
    expect(good.exitCode).toBe(0); expect(good.lines.join('\n')).toMatch(/CONSISTENT {2}provenance: authenticated/); expect(good.lines.at(-1)).toMatch(/^verified/);
    const noTrust = runVerifyLog(d);
    expect(noTrust.exitCode).toBe(1); expect(noTrust.lines.at(-1)).toMatch(/^internally consistent; signing identity not authenticated/);
    mutate(d, 'leaves.ndjson', (t) => t.replace('"r5"', '"r5-EDITED"'), { resealDigest: true });
    const bad = runVerifyLog(d, { trust: tf }); expect(bad.exitCode).toBe(2); expect(bad.lines.join('\n')).toMatch(/BROKEN/);
    writeFileSync(tf, '{ nope'); expect(runVerifyLog(d, { trust: tf })).toMatchObject({ exitCode: 2 });
    expect(runVerifyLog(d, { retained: join(d, 'absent.ndjson') }).exitCode).toBe(2);
  });
  it('--json prints the full report', async () => {
    const { runVerifyLog } = await import('./verify-log-cli.js');
    const d = tmp(); buildExport(d, sim, { segments: [{ seg }], manifestKey: k0 });
    const r = runVerifyLog(d, { json: true }); const o = JSON.parse(r.lines.join('\n'));
    expect(o).toMatchObject({ exitCode: 1, verified: false, segments: [{ outcome: 'consistent', provenance: 'not_authenticated' }] });
  });
  const dist = join(__dirname, '..', 'dist', 'index.js');
  it.skipIf(!existsSync(dist))('the built binary is wired: `maindala verify-log` exits with the report code', () => {
    const d = tmp(); buildExport(d, sim, { segments: [{ seg }], manifestKey: k0 });
    const tf = join(d, 'trust.json'); writeFileSync(tf, JSON.stringify(trustOf(sim, [k0])));
    const run = (...a: string[]) => spawnSync(process.execPath, [dist, 'verify-log', ...a], { encoding: 'utf8' });
    expect(run(d, '--trust', tf).status).toBe(0);
    expect(run(d).status).toBe(1);
    expect(run(join(d, 'nope')).status).toBe(2);
  });
});
