// Test-only simulator of a log installation and its exports, written from the format specification (docs/verify-log-format.md) and
// using only the verifier's own primitives plus node:crypto. It can produce honest exports and attacks (rewrites, truncation,
// replacement, rotation to an attacker key). The origin/key-name prefix is a parameter because the verifier treats it as opaque.
import { createHash, generateKeyPairSync, randomUUID, sign, createPublicKey, type KeyObject } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalize } from '../src/log-jcs.js';
import { mth, leafHashOf, decompose, consistencyPath } from '../src/log-merkle.js';
import { c2spKeyHash, fingerprintOf } from '../src/signed-note.js';

export const jcs = (v: unknown): Buffer => Buffer.from(canonicalize(v) as string, 'utf8');
const sha = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');

export interface SimKey { priv: KeyObject; pub: Buffer; fp: string; kid: string; name: string }
export interface SimLeaf { kind: string; ts: string; body: Record<string, unknown> }
export interface SimCheckpoint { size: number; key: SimKey; ts: string; rootOverride?: Buffer }

export class Sim {
  installationId: string;
  prefix: string;
  keys: SimKey[] = [];
  constructor(installationId: string = randomUUID(), prefix = 'evlog') { this.installationId = installationId; this.prefix = prefix; }
  get keyName(): string { return `${this.prefix}/${this.installationId}`; }
  newKey(): SimKey {
    const { privateKey } = generateKeyPairSync('ed25519');
    const pub = (createPublicKey(privateKey).export({ type: 'spki', format: 'der' }) as Buffer).subarray(-32);
    const name = this.keyName;
    const k = { priv: privateKey, pub, fp: fingerprintOf(pub), kid: c2spKeyHash(name, pub).toString('hex'), name };
    this.keys.push(k);
    return k;
  }
}

export class SimSeg {
  leaves: SimLeaf[] = [];
  checkpoints: SimCheckpoint[] = [];
  constructor(public sim: Sim, public id = randomUUID(), public meta: { reason?: string; previousSegmentId?: string | null; link?: unknown; status?: string } = {}) {}
  add(kind: string, body: Record<string, unknown> = {}, ts = new Date(Date.UTC(2026, 10, 25, 12, 0, this.leaves.length)).toISOString()): number {
    this.leaves.push({ kind, ts, body });
    return this.leaves.length - 1;
  }
  hashes(): Buffer[] { return this.leaves.map((l) => leafHashOf(jcs(l))); }
  root(size = this.leaves.length): Buffer { return mth(this.hashes().slice(0, size)); }
  checkpoint(key: SimKey, size = this.leaves.length, ts?: string): SimCheckpoint {
    const cp = { size, key, ts: ts ?? this.leaves[size - 1]?.ts ?? new Date().toISOString() };
    this.checkpoints.push(cp);
    return cp;
  }
  note(cp: SimCheckpoint): string {
    const body = `${this.sim.keyName}/${this.id}\n${cp.size}\n${(cp.rootOverride ?? this.root(cp.size)).toString('base64')}\n`;
    const sig = sign(null, Buffer.from(body, 'utf8'), cp.key.priv);
    return `${body}\n— ${cp.key.name} ${Buffer.concat([c2spKeyHash(cp.key.name, cp.key.pub), sig]).toString('base64')}\n`;
  }
  /** A deep copy of the leaves and checkpoints so an attack can diverge from the honest history. */
  fork(newId = this.id): SimSeg { const s = new SimSeg(this.sim, newId, this.meta); s.leaves = this.leaves.map((l) => ({ ...l, body: { ...l.body } })); s.checkpoints = this.checkpoints.map((c) => ({ ...c })); return s; }
}

export interface SegSpec { seg: SimSeg; from?: number; to?: number; target?: number; cut?: { size: number; earlierProofs?: number[] } }
export interface BuildSpec { segments: SegSpec[]; manifestKey: SimKey; keys?: SimKey[]; exportedAt?: string }

const hex = (b: Buffer): string => b.toString('hex');

// Writes an export directory exactly as the format specification describes.
export function buildExport(dir: string, sim: Sim, spec: BuildSpec): void {
  mkdirSync(dir, { recursive: true });
  const files = new Map<string, Buffer>();
  const leafLines: unknown[] = []; const cpLines: unknown[] = []; const proofs: Record<string, unknown> = {}; const segs: unknown[] = [];
  const ranges: unknown[] = [];
  for (const sp of spec.segments) {
    const s = sp.seg; const hs = s.hashes();
    const target = sp.target ?? Math.max(...s.checkpoints.map((c) => c.size));
    const cutSize = sp.cut?.size ?? 0;
    const from = sp.from ?? cutSize; const to = sp.to ?? target;
    const sub = (lo: number, hi: number): Buffer => mth(hs.slice(lo, hi));
    const left = decompose(0, from).map((d) => sub(d.pos, d.pos + 2 ** d.level));
    const right = decompose(to, target).map((d) => sub(d.pos, d.pos + 2 ** d.level));
    for (let i = from; i < to; i++) leafLines.push({ segmentId: s.id, index: i, kind: s.leaves[i]!.kind, ts: s.leaves[i]!.ts, body: s.leaves[i]!.body, leafHash: hex(hs[i]!) });
    for (const c of s.checkpoints.filter((x) => x.size <= target)) cpLines.push({ segmentId: s.id, size: c.size, rootHash: hex(c.rootOverride ?? s.root(c.size)), kid: c.key.kid, ts: c.ts, note: s.note(c) });
    const consistency = s.checkpoints.filter((c) => c.size <= target && c.size !== target && c.size >= 1 && !(c.size >= from && c.size <= to) && c.size >= cutSize)
      .map((c) => ({ from: c.size, to: target, proof: consistencyPath(c.size, hs.slice(0, target)).map(hex) }));
    const retention: unknown[] = [];
    if (sp.cut) {
      const k = sp.cut.size;
      const cpK = s.checkpoints.find((c) => c.size === k)!;
      retention.push({
        cutSize: k, compactRange: decompose(0, k).map((d) => hex(sub(d.pos, d.pos + 2 ** d.level))),
        checkpoint: { size: k, rootHash: hex(s.root(k)), kid: cpK.key.kid, ts: cpK.ts, note: s.note(cpK) },
        proofs: s.checkpoints.filter((c) => c.size < k && c.size >= 1).map((c) => ({ from: c.size, proof: consistencyPath(c.size, hs.slice(0, k)).map(hex) })),
      });
    }
    proofs[s.id] = { targetSize: target, left: left.map(hex), right: right.map(hex), consistency, retention };
    segs.push({ segmentId: s.id, startedAt: '2026-11-25T12:00:00.000Z', reason: s.meta.reason ?? 'install', previousSegmentId: s.meta.previousSegmentId ?? null, link: s.meta.link ?? null, status: s.meta.status ?? 'open', range: { from, to, targetSize: target } });
    ranges.push({ segmentId: s.id, from, to, targetSize: target });
  }
  const lines = (xs: unknown[]): Buffer => Buffer.from(xs.map((x) => jcs(x).toString('utf8') + '\n').join(''), 'utf8');
  files.set('leaves.ndjson', lines(leafLines));
  files.set('checkpoints.ndjson', lines(cpLines));
  files.set('proofs.json', jcs({ segments: proofs }));
  files.set('segment.json', jcs({ segments: segs }));
  const keys = spec.keys ?? sim.keys;
  files.set('key-history.json', jcs({ installationId: sim.installationId, keyName: sim.keyName, keys: keys.map((k) => ({ kid: k.kid, publicKey: k.pub.toString('base64'), fingerprint: k.fp })), events: [] }));
  files.set('VERIFY.md', Buffer.from('verify me\n'));
  files.set('CONFIDENTIAL.txt', Buffer.from('confidential\n'));
  const manifest = jcs({
    formatVersion: 1, tool: 'sim', installationId: sim.installationId, exportedAt: spec.exportedAt ?? '2026-11-26T00:00:00.000Z', signingKid: spec.manifestKey.kid, signingFingerprint: spec.manifestKey.fp,
    files: Object.fromEntries([...files].map(([n, b]) => [n, sha(b)])), segments: ranges,
  });
  files.set('manifest.json', manifest);
  files.set('manifest.sig', jcs({ kid: spec.manifestKey.kid, signature: sign(null, manifest, spec.manifestKey.priv).toString('base64') }));
  for (const [n, b] of files) writeFileSync(join(dir, n), b);
}

/** Rewrites one file of an export directory and re-seals the manifest digest (but not the signature) so a test reaches the segment checks. */
export function mutate(dir: string, file: string, fn: (text: string) => string, opts: { resealDigest?: boolean } = {}): void {
  writeFileSync(join(dir, file), fn(readFileSync(join(dir, file), 'utf8')));
  if (opts.resealDigest) {
    const m = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'));
    m.files[file] = sha(readFileSync(join(dir, file)));
    writeFileSync(join(dir, 'manifest.json'), jcs(m));
  }
}

export const trustOf = (sim: Sim, pins: SimKey[], extra: Record<string, unknown> = {}) => ({
  installationId: sim.installationId,
  pinnedKeys: pins.map((k) => ({ fingerprint: k.fp, kid: k.kid, pinnedAt: '2026-11-25T00:00:00.000Z' })),
  ...extra,
});

export const retainedEntry = (seg: SimSeg, cp: SimCheckpoint, prev?: SimCheckpoint) => ({
  segmentId: seg.id, size: cp.size, rootHash: hex(seg.root(cp.size)), kid: cp.key.kid, ts: cp.ts, note: seg.note(cp), publicKey: cp.key.pub.toString('base64'),
  prev: prev ? { size: prev.size, rootHash: hex(seg.root(prev.size)), proof: consistencyPath(prev.size, seg.hashes().slice(0, cp.size)).map(hex) } : null,
});
