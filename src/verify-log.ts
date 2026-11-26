// Offline verifier for signed, append-only evidence log exports (format: docs/verify-log-format.md). Reads an export directory and
// reports, per segment, a structural OUTCOME (consistent | rolled_back | conflicting_history | broken) and, separately, PROVENANCE
// (authenticated | not_authenticated | revoked) judged only against a trust anchor supplied from outside the export. No network.
// "verified" is reported only when the outcome is consistent AND the provenance is authenticated.
import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalize } from './log-jcs.js';
import { checkConsistency, decompose, foldParts, leafHashOf, levelsOf, Peaks } from './log-merkle.js';
import { parseNote, c2spKeyHash, fingerprintOf, ed25519Ok } from './signed-note.js';

export const SUPPORTED_FORMAT_VERSION = 1;

// ── Public types ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
export interface RetainedEntry {
  segmentId: string; size: number; rootHash: string; kid?: string; ts?: string; note: string; publicKey?: string;
  prev?: { size: number; rootHash: string; proof: string[] } | null;
}
export interface TrustFile {
  installationId: string;
  pinnedKeys: { fingerprint: string; kid?: string; pinnedAt?: string; revokedSince?: string }[];
  retainedCheckpoints?: RetainedEntry[];
}
export interface VerifyOptions { trust?: TrustFile; retained?: RetainedEntry[] }

export type Outcome = 'consistent' | 'rolled_back' | 'conflicting_history' | 'broken';
export type Provenance = 'authenticated' | 'not_authenticated' | 'revoked';

export interface SegmentReport {
  segmentId: string;
  outcome: Outcome;
  /** Qualifiers on a consistent outcome: history_not_included, retained_unrelated, checkpoint_not_checked, no_checkpoint. */
  qualifiers: string[];
  historyNotIncluded: { from: number; to: number; reason: 'outside_exported_range' | 'pruned_by_retention_cut' }[];
  /** Why the outcome is broken: the first failing index when known, else the range it lies in. */
  broken: { reason: string; index?: number; between?: [number, number]; detail: string }[];
  conflicts: string[];
  rolledBack: { retainedSize: number; exportSize: number; unavailable: [number, number] } | null;
  provenance: Provenance;
  provenanceDetail: string;
  verified: boolean;
  checkpoints: number;
  targetSize: number;
  range: { from: number; to: number };
  recovery: { previousSegmentId: string; reason: string; reasonText: string | null; previousIncluded: boolean; previousOutcome: Outcome | null; linkCheckpointFound: boolean | null } | null;
  uncertainOutcomes: number;
  informationalRevocations: { kid: string; compromisedSince: string }[];
  clockRegressions: { leafLeaves: number; observed: number };
  warnings: string[];
}

export interface Report {
  formatVersion: number | null;
  installationId: string | null;
  manifest: { ok: boolean; problems: string[]; signedBy: { kid: string; fingerprint: string; trusted: boolean } | null };
  trust: { provided: boolean; installationMatches: boolean | null; pinnedKeyInExport: boolean | null };
  keys: { kid: string; fingerprint: string; trusted: boolean; via: 'pinned' | 'rotation' | null; revokedSince: string | null }[];
  segments: SegmentReport[];
  warnings: string[];
  failures: string[];
  verified: boolean;
  exitCode: 0 | 1 | 2;
  summary: string;
}

// ── Small helpers ────────────────────────────────────────────────────────────────────────────────────────────────────────────
const sha = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');
const hexBuf = (h: string): Buffer => Buffer.from(h, 'hex');
const isHash = (h: unknown): h is string => typeof h === 'string' && /^[0-9a-f]{64}$/.test(h);
const jcsBytes = (v: unknown): Buffer => { const s = canonicalize(v); if (s === undefined) throw new Error('not canonicalizable'); return Buffer.from(s, 'utf8'); };
const ndjson = (text: string): any[] => text.split('\n').filter((l) => l.trim().length).map((l) => JSON.parse(l));
const t = (v: unknown): number | null => { const n = typeof v === 'string' ? Date.parse(v) : NaN; return Number.isNaN(n) ? null : n; };

interface KeyInfo { kid: string; publicKey: Buffer; fingerprint: string }
interface CpInfo { size: number; root: Buffer; kid: string; fingerprint: string; time: number | null; sigValid: boolean; verified: boolean; ts: string }
interface SegData {
  id: string; row: any; a: number; b: number; n: number;
  leaves: { index: number; kind: string; ts: string; body: any; leafHash: string }[];
  cps: CpInfo[];
  proofs: any;
  analysis: SegmentReport;
  rootAt: Map<number, Buffer>;
  hashes: Buffer[];
}

// ── Loading ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
function read(dir: string, name: string, problems: string[], required = true): Buffer | null {
  const p = join(dir, name);
  if (!existsSync(p)) { if (required) problems.push(`missing file ${name}`); return null; }
  return readFileSync(p);
}
function parseJson(buf: Buffer | null, name: string, problems: string[]): any {
  if (!buf) return null;
  try { return JSON.parse(buf.toString('utf8')); } catch { problems.push(`${name} is not valid JSON`); return null; }
}

/** Verifies an export directory against an optional trust anchor and optional retained checkpoints. */
export function verifyExport(dir: string, opts: VerifyOptions = {}): Report {
  const warnings: string[] = [];
  const failures: string[] = [];
  const mProblems: string[] = [];

  // ── Manifest and file digests ──
  const manifestBuf = read(dir, 'manifest.json', mProblems);
  const manifest = parseJson(manifestBuf, 'manifest.json', mProblems);
  const sigFile = parseJson(read(dir, 'manifest.sig', mProblems), 'manifest.sig', mProblems);
  const formatVersion: number | null = typeof manifest?.formatVersion === 'number' ? manifest.formatVersion : null;
  if (manifest && (formatVersion === null || formatVersion > SUPPORTED_FORMAT_VERSION || formatVersion < 1)) mProblems.push(`unsupported format version ${String(manifest.formatVersion)}`);
  const buffers = new Map<string, Buffer>();
  for (const f of ['leaves.ndjson', 'checkpoints.ndjson', 'proofs.json', 'segment.json', 'key-history.json']) {
    const b = read(dir, f, mProblems);
    if (b) buffers.set(f, b);
  }
  if (manifest?.files && typeof manifest.files === 'object') {
    for (const [name, digest] of Object.entries<string>(manifest.files)) {
      const b = name === 'VERIFY.md' || name === 'CONFIDENTIAL.txt' ? read(dir, name, mProblems, false) : (buffers.get(name) ?? read(dir, name, mProblems));
      if (b && sha(b) !== digest) mProblems.push(`${name} does not match its manifest digest`);
    }
    for (const f of buffers.keys()) if (!(f in manifest.files)) mProblems.push(`${f} is not listed in the manifest`);
  } else if (manifest) mProblems.push('manifest lists no files');

  // ── Key history (public keys only; advisory: authority comes from the trust anchor) ──
  const kh = parseJson(buffers.get('key-history.json') ?? null, 'key-history.json', mProblems);
  const installationId: string | null = typeof kh?.installationId === 'string' ? kh.installationId : (typeof manifest?.installationId === 'string' ? manifest.installationId : null);
  if (kh && manifest && kh.installationId !== manifest.installationId) mProblems.push('manifest and key history name different installations');
  // The signing key name and every checkpoint origin are `<prefix>/<installationId>[/<segmentId>]`. The prefix is chosen by the producer
  // and is opaque here: it is read from the key history's keyName, which must be exactly `<prefix>/<installationId>`. Notes and
  // origins are then required to agree with it. (The prefix is not a trust input: authority comes only from the pinned keys.)
  const keyName: string | null = installationId && typeof kh?.keyName === 'string' && /^[^\s/]+(\/[^\s/]+)*$/.test(kh.keyName) && kh.keyName.endsWith(`/${installationId}`) && kh.keyName.length > installationId.length + 1 ? kh.keyName : null;
  if (kh && installationId && !keyName) mProblems.push('key history has no usable key name of the form <prefix>/<installationId>');
  const keysByKid = new Map<string, KeyInfo>();
  const addKey = (publicKeyB64: string, claimedKid?: string): KeyInfo | null => {
    if (!installationId || !keyName) return null;
    const pub = Buffer.from(publicKeyB64, 'base64');
    if (pub.length !== 32) return null;
    const name = keyName;
    const kid = c2spKeyHash(name, pub).toString('hex');
    if (claimedKid !== undefined && claimedKid !== kid) { warnings.push(`key ${claimedKid} in the key history does not match its public key; ignored`); return null; }
    const k = { kid, publicKey: pub, fingerprint: fingerprintOf(pub) };
    keysByKid.set(kid, k);
    return k;
  };
  for (const k of kh?.keys ?? []) if (typeof k?.publicKey === 'string') addKey(k.publicKey, k.kid);

  // ── Segments ──
  const segJson = parseJson(buffers.get('segment.json') ?? null, 'segment.json', mProblems);
  const allLeaves: any[] = []; const allCps: any[] = [];
  try { allLeaves.push(...ndjson((buffers.get('leaves.ndjson') ?? Buffer.alloc(0)).toString('utf8'))); } catch { mProblems.push('leaves.ndjson has a line that is not JSON'); }
  try { allCps.push(...ndjson((buffers.get('checkpoints.ndjson') ?? Buffer.alloc(0)).toString('utf8'))); } catch { mProblems.push('checkpoints.ndjson has a line that is not JSON'); }
  const proofsJson = parseJson(buffers.get('proofs.json') ?? null, 'proofs.json', mProblems);

  const segs: SegData[] = [];
  for (const row of segJson?.segments ?? []) {
    const id = String(row.segmentId);
    const a = Number(row.range?.from), b = Number(row.range?.to), n = Number(row.range?.targetSize);
    const data: SegData = {
      id, row, a, b, n,
      leaves: allLeaves.filter((l) => l.segmentId === id).sort((x, y) => x.index - y.index),
      cps: [], proofs: proofsJson?.segments?.[id] ?? {}, rootAt: new Map(), hashes: [],
      analysis: {
        segmentId: id, outcome: 'consistent', qualifiers: [], historyNotIncluded: [], broken: [], conflicts: [], rolledBack: null, provenance: 'not_authenticated',
        provenanceDetail: '', verified: false, checkpoints: 0, targetSize: n, range: { from: a, to: b }, recovery: null, uncertainOutcomes: 0,
        informationalRevocations: [], clockRegressions: { leafLeaves: 0, observed: 0 }, warnings: [],
      },
    };
    segs.push(data);
  }
  for (const s of segs) analyseSegment(s, allCps.filter((c) => c.segmentId === s.id), keyName, keysByKid, warnings);

  // ── Trust ──
  const trust = opts.trust;
  const anchorMatches: boolean | null = trust ? trust.installationId === installationId : null;
  const pins = new Map<string, { revokedSince: number | null; revokedSinceText: string | null }>();
  if (trust && anchorMatches) for (const p of trust.pinnedKeys ?? []) pins.set(p.fingerprint, { revokedSince: t(p.revokedSince), revokedSinceText: p.revokedSince ?? null });
  const trusted = new Map<string, 'pinned' | 'rotation'>();
  for (const fp of pins.keys()) trusted.set(fp, 'pinned');
  const revokedAt = (fp: string, time: number | null): boolean => {
    const rs = pins.get(fp)?.revokedSince;
    if (rs === null || rs === undefined) return false;
    return time === null ? true : time >= rs;
  };
  // Rotation extends trust only through a key_rotation leaf committed under a VERIFIED checkpoint signed by an already-trusted key that was
  // not revoked (per the anchor) at the checkpoint's time or the leaf's time. Fixpoint over all segments (a rotation in one segment carries
  // into the next).
  const rotations: { seg: SegData; idx: number; ts: number | null; oldFp: string; newKey: KeyInfo }[] = [];
  for (const s of segs) {
    for (const l of s.leaves) {
      if (l.kind !== 'key_rotation' || typeof l.body?.newPublicKey !== 'string' || typeof l.body?.oldFingerprint !== 'string') continue;
      const nk = addKey(l.body.newPublicKey);
      if (!nk || nk.fingerprint !== l.body.newFingerprint || nk.kid !== l.body.newKid) { s.analysis.warnings.push(`key_rotation leaf ${l.index} is inconsistent with its own key; ignored`); continue; }
      rotations.push({ seg: s, idx: l.index, ts: t(l.ts), oldFp: l.body.oldFingerprint, newKey: nk });
    }
  }
  for (let changed = true; changed;) {
    changed = false;
    for (const r of rotations) {
      if (trusted.has(r.newKey.fingerprint) || !trusted.has(r.oldFp) || revokedAt(r.oldFp, r.ts)) continue;
      const cover = r.seg.cps.find((c) => c.verified && c.sigValid && c.fingerprint === r.oldFp && c.size > r.idx && !revokedAt(r.oldFp, c.time));
      if (cover) { trusted.set(r.newKey.fingerprint, 'rotation'); changed = true; }
    }
  }
  const pinnedKeyInExport = trust && anchorMatches ? [...pins.keys()].some((fp) => [...keysByKid.values()].some((k) => k.fingerprint === fp)) : null;
  if (trust && anchorMatches === false) failures.push('trust anchor is for a different installation');
  if (trust && anchorMatches && pinnedKeyInExport === false) failures.push('signing key not trusted for this installation: no pinned key appears in this export');

  // ── Manifest signature and provenance ──
  let signedBy: Report['manifest']['signedBy'] = null;
  if (manifestBuf && sigFile && typeof sigFile.kid === 'string' && typeof sigFile.signature === 'string') {
    const k = keysByKid.get(sigFile.kid);
    if (!k) mProblems.push('manifest is signed by a key that is not in the key history');
    else if (!ed25519Ok(k.publicKey, manifestBuf, Buffer.from(sigFile.signature, 'base64'))) mProblems.push('manifest signature is invalid');
    else signedBy = { kid: k.kid, fingerprint: k.fingerprint, trusted: trusted.has(k.fingerprint) && !revokedAt(k.fingerprint, t(manifest?.exportedAt)) };
  } else if (manifestBuf) mProblems.push('manifest.sig is missing or malformed');

  // ── Retained checkpoints, then per-segment provenance and final outcomes ──
  const retained = collectRetained(opts, keyName, keysByKid, trust ? { trusted, revokedAt } : null, warnings);
  for (const s of segs) {
    applyRetained(s, retained.filter((r) => r.segmentId === s.id));
    provenanceOf(s, trust ? { trusted, revokedAt, pins } : null, keysByKid);
  }
  // Recovery links and chain checks.
  for (const s of segs) {
    const start = s.leaves.find((l) => l.index === 0 && l.kind === 'segment_start');
    const prevId = start?.body?.previousSegmentId ?? s.row.previousSegmentId;
    if (prevId) {
      const prev = segs.find((x) => x.id === prevId) ?? null;
      const link = start?.body?.previousCheckpoint ?? s.row.link?.previousCheckpoint ?? null;
      const found = link && prev ? prev.cps.some((c) => c.size === link.size && c.root.toString('hex') === link.rootHash) : null;
      s.analysis.recovery = { previousSegmentId: prevId, reason: String(start?.body?.reason ?? s.row.reason), reasonText: start?.body?.reasonText ?? null, previousIncluded: !!prev, previousOutcome: prev?.analysis.outcome ?? null, linkCheckpointFound: found };
      if (prev && found === false) s.analysis.warnings.push('the recovery link names a checkpoint that is not among the previous segment\'s checkpoints');
      if (prev && prev.analysis.outcome === 'broken') s.analysis.warnings.push('recovery after a broken segment: the earlier segment remains broken');
      if (prev && prev.analysis.outcome === 'rolled_back') s.analysis.warnings.push('recovery after a restore: the earlier segment is rolled back behind a retained checkpoint');
    }
  }

  const reports = segs.map((s) => s.analysis);
  const keys: Report['keys'] = [...new Map([...keysByKid.values()].map((k) => [k.fingerprint, k])).values()].map((k) => ({
    kid: k.kid, fingerprint: k.fingerprint, trusted: trusted.has(k.fingerprint), via: trusted.get(k.fingerprint) ?? null, revokedSince: pins.get(k.fingerprint)?.revokedSinceText ?? null,
  }));
  if (mProblems.length) failures.push(...mProblems.map((p) => `manifest: ${p}`));
  for (const r of reports) {
    if (r.outcome === 'broken') failures.push(`segment ${r.segmentId} is broken`);
    if (r.outcome === 'conflicting_history') failures.push(`segment ${r.segmentId} has conflicting history`);
  }
  const everySegmentVerified = reports.length > 0 && reports.every((r) => r.verified);
  const manifestOk = mProblems.length === 0;
  const verified = !!trust && failures.length === 0 && manifestOk && !!signedBy?.trusted && everySegmentVerified;
  const exitCode: 0 | 1 | 2 = failures.length ? 2 : verified ? 0 : 1;
  return {
    formatVersion, installationId, manifest: { ok: manifestOk, problems: mProblems, signedBy },
    trust: { provided: !!trust, installationMatches: anchorMatches, pinnedKeyInExport }, keys, segments: reports, warnings, failures, verified, exitCode,
    summary: summarise(exitCode, !!trust, reports, failures),
  };
}

function summarise(code: 0 | 1 | 2, hasAnchor: boolean, segs: SegmentReport[], failures: string[]): string {
  if (code === 0) return 'verified: consistent and the signing identity is authenticated against the trust anchor';
  if (code === 2) return `FAILED: ${failures[0] ?? 'verification failed'}`;
  if (!hasAnchor) return 'internally consistent; signing identity not authenticated (no trust anchor supplied)';
  if (segs.some((s) => s.outcome === 'rolled_back')) return 'consistent as far as it goes, but rolled back behind a retained checkpoint: not verified';
  return 'internally consistent; signing identity not (fully) authenticated against the trust anchor';
}

// ── Per-segment structural analysis ──────────────────────────────────────────────────────────────────────────────────────────
function analyseSegment(s: SegData, cpRows: any[], keyName: string | null, keys: Map<string, KeyInfo>, warnings: string[]): void {
  const r = s.analysis;
  const bad = (reason: string, detail: string, index?: number, between?: [number, number]): void => { r.broken.push({ reason, detail, ...(index !== undefined ? { index } : {}), ...(between ? { between } : {}) }); };

  // Leaves: exactly the declared range, gapless, hashes recomputed from content.
  const byIndex = new Map<number, (typeof s.leaves)[number]>();
  for (const l of s.leaves) {
    if (byIndex.has(l.index)) bad('duplicate_index', `leaf index ${l.index} appears twice`, l.index);
    byIndex.set(l.index, l);
  }
  for (let i = s.a; i < s.b; i++) if (!byIndex.has(i)) { bad('missing_index', `leaf ${i} is missing from the exported range`, i); break; }
  for (const l of s.leaves) if (l.index < s.a || l.index >= s.b) { bad('unexpected_leaf', `leaf ${l.index} is outside the declared range [${s.a}, ${s.b})`, l.index); break; }
  const hashes: Buffer[] = [];
  let hashFailure = false;
  for (let i = s.a; i < s.b; i++) {
    const l = byIndex.get(i);
    if (!l) { hashFailure = true; break; }
    let h: Buffer;
    try { h = leafHashOf(jcsBytes({ kind: l.kind, ts: l.ts, body: l.body })); } catch { bad('leaf_not_canonical', `leaf ${i} cannot be canonicalized`, i); hashFailure = true; break; }
    if (l.leafHash !== h.toString('hex')) { bad('leaf_hash_mismatch', `leaf ${i} content does not match its recorded hash`, i); hashFailure = true; }
    hashes.push(h);
  }
  s.hashes = hashes;
  // Boundaries.
  const pr = s.proofs ?? {};
  const left: Buffer[] = Array.isArray(pr.left) && pr.left.every(isHash) ? pr.left.map(hexBuf) : [];
  const right: Buffer[] = Array.isArray(pr.right) && pr.right.every(isHash) ? pr.right.map(hexBuf) : [];
  if (left.length !== levelsOf(s.a).length) bad('bad_left_boundary', `left compact range has ${left.length} hashes, expected ${levelsOf(s.a).length}`);
  if (right.length !== decompose(s.b, s.n).length) bad('bad_right_boundary', `right compact range has ${right.length} hashes, expected ${decompose(s.b, s.n).length}`);
  if (s.b > s.n || s.a > s.b) bad('bad_range', `range [${s.a}, ${s.b}) with target ${s.n} is not valid`);
  const boundaryOk = left.length === levelsOf(s.a).length && right.length === decompose(s.b, s.n).length && s.b <= s.n && s.a <= s.b;

  // Checkpoints: note, origin, size, root and signature. Roots are checked against the tree where the data allows.
  for (const row of cpRows) {
    let note: ReturnType<typeof parseNote>;
    try { note = parseNote(String(row.note)); } catch (e) { bad('checkpoint_malformed', `a checkpoint note is malformed: ${(e as Error).message}`); continue; }
    if (keyName && note.origin !== `${keyName}/${s.id}`) { bad('checkpoint_origin', `checkpoint of size ${note.size} has origin ${note.origin}`); continue; }
    if (note.size !== row.size || note.root.toString('hex') !== row.rootHash) { bad('checkpoint_record_mismatch', `checkpoint record of size ${row.size} does not match its signed note`); continue; }
    const name = keyName ?? '';
    let signer: KeyInfo | null = null; let sigValid = false;
    for (const sg of note.sigs) {
      if (sg.name !== name) continue;
      for (const k of keys.values()) {
        if (c2spKeyHash(name, k.publicKey).equals(sg.keyHash) && ed25519Ok(k.publicKey, Buffer.from(note.body, 'utf8'), sg.sig)) { signer = k; sigValid = true; }
      }
    }
    if (!sigValid || !signer) { bad('checkpoint_signature', `checkpoint of size ${note.size} has no valid signature by a key in the key history`, undefined, undefined); continue; }
    s.cps.push({ size: note.size, root: note.root, kid: signer.kid, fingerprint: signer.fingerprint, time: null, sigValid, verified: false, ts: String(row.ts ?? '') });
  }
  s.cps.sort((x, y) => x.size - y.size);
  r.checkpoints = s.cps.length;

  // Same size, different roots (both validly signed): a fork inside the export itself.
  for (const c of s.cps) {
    const twin = s.cps.find((o) => o !== c && o.size === c.size && !o.root.equals(c.root));
    if (twin && !r.conflicts.some((x) => x.includes(`size ${c.size}`))) r.conflicts.push(`two valid checkpoints of size ${c.size} commit to different roots`);
  }

  // Roots computable from the left boundary and the leaves: sizes in [a, b].
  if (boundaryOk && !hashFailure) {
    const p = Peaks.from(s.a, left);
    s.rootAt.set(s.a, p.root());
    hashes.forEach((h, i) => { p.push(h, 0); s.rootAt.set(s.a + i + 1, p.root()); });
    let target: Buffer | null = null;
    try { target = foldParts(s.a, left, hashes, s.n, right); } catch { bad('bad_boundaries', 'compact ranges could not be folded'); }
    if (target) s.rootAt.set(s.n, target);
  }

  const cuts: any[] = Array.isArray(pr.retention) ? pr.retention : [];
  const cutRoots = new Map<number, Buffer>();
  for (const cut of cuts) {
    try {
      const k = Number(cut.cutSize);
      const folded = Peaks.from(k, (cut.compactRange as string[]).map(hexBuf)).root();
      cutRoots.set(k, folded);
      if (cut.checkpoint?.rootHash !== folded.toString('hex')) bad('retention_cut_root', `retention cut ${k}: compact range does not fold to the cut checkpoint root`);
      const cpAtK = s.cps.find((c) => c.size === k);
      if (cpAtK && !cpAtK.root.equals(folded)) bad('retention_cut_root', `retention cut ${k}: compact range does not fold to the signed checkpoint at ${k}`);
      const leaf = s.leaves.find((l) => l.kind === 'retention_cut' && l.body?.cutSize === k);
      if (leaf && leaf.body.rootHash !== folded.toString('hex')) bad('retention_cut_leaf', `retention cut ${k}: the retention_cut leaf names a different root`);
      if (s.a === k && boundaryOk && left.some((h, i) => !h.equals(hexBuf((cut.compactRange as string[])[i]!)))) bad('retention_cut_boundary', `left boundary differs from the compact range of cut ${k}`);
    } catch { bad('retention_cut_malformed', 'a retention cut record is malformed'); }
  }
  const latestCut = cuts.length ? Math.max(...cuts.map((c) => Number(c.cutSize))) : 0;
  if (s.a > 0) r.historyNotIncluded.push({ from: 0, to: s.a, reason: s.a <= latestCut ? 'pruned_by_retention_cut' : 'outside_exported_range' });
  if (s.n > s.b) r.historyNotIncluded.push({ from: s.b, to: s.n, reason: 'outside_exported_range' });
  if (r.historyNotIncluded.length) r.qualifiers.push('history_not_included');

  // Verify each checkpoint's root. Direct where computable; by consistency proof to the target; by retention proof below a cut.
  const target = s.rootAt.get(s.n);
  if (!s.cps.some((c) => c.size === s.n)) bad('no_target_checkpoint', `no valid checkpoint of the target size ${s.n}`);
  if (!s.cps.length) r.qualifiers.push('no_checkpoint');
  const proofList: any[] = Array.isArray(pr.consistency) ? pr.consistency : [];
  let lastGood = s.a > 0 ? 0 : 0;
  let firstMismatch: number | null = null;
  for (const c of s.cps) {
    const direct = s.rootAt.get(c.size);
    if (direct) {
      if (!direct.equals(c.root)) {
        bad('checkpoint_root_mismatch', `the root of the first ${c.size} leaves does not match the checkpoint`);
        if (firstMismatch === null) firstMismatch = c.size;
      } else { c.verified = true; if (firstMismatch === null) lastGood = c.size; }
      continue;
    }
    const cp = proofList.find((x) => Number(x.from) === c.size && Number(x.to) === s.n);
    if (cp && target && Array.isArray(cp.proof) && cp.proof.every(isHash)) {
      if (checkConsistency(c.size, s.n, c.root, target, cp.proof.map(hexBuf))) c.verified = true;
      else { bad('consistency_proof_failed', `checkpoint ${c.size} is not consistent with the target checkpoint ${s.n}`, undefined, [c.size, s.n]); if (firstMismatch === null) firstMismatch = c.size; }
      continue;
    }
    // Below a retention cut: the stored proofs from the checkpoint to the cut.
    const viaCut = cuts.find((cut) => Number(cut.cutSize) > c.size && Array.isArray(cut.proofs) && cut.proofs.some((p: any) => Number(p.from) === c.size));
    if (viaCut) {
      const pf = viaCut.proofs.find((p: any) => Number(p.from) === c.size);
      const rk = cutRoots.get(Number(viaCut.cutSize));
      if (rk && Array.isArray(pf.proof) && checkConsistency(c.size, Number(viaCut.cutSize), c.root, rk, pf.proof.map(hexBuf))) c.verified = true;
      else bad('retention_proof_failed', `checkpoint ${c.size} is not consistent with retention cut ${viaCut.cutSize}`, undefined, [c.size, Number(viaCut.cutSize)]);
      continue;
    }
    if (!r.qualifiers.includes('checkpoint_not_checked')) r.qualifiers.push('checkpoint_not_checked');
    r.warnings.push(`checkpoint of size ${c.size} could not be checked against this export (no leaves or proof cover it)`);
  }
  // Narrow a root mismatch: the break lies after the last checkpoint that did verify and before the first that did not.
  if (firstMismatch !== null && !r.broken.some((x) => x.index !== undefined)) {
    const prevOk = Math.max(s.a, ...s.cps.filter((c) => c.verified && c.size < firstMismatch!).map((c) => c.size));
    const lo = Number.isFinite(prevOk) ? prevOk : s.a;
    r.broken.push({ reason: 'break_located', detail: `the first affected leaf lies in [${lo}, ${firstMismatch})`, between: [lo, firstMismatch] });
  }
  void lastGood;

  // Checkpoint times: the timestamp of the last leaf a checkpoint covers (committed by its root), else the unsigned record time.
  for (const c of s.cps) {
    const l = byIndex.get(c.size - 1);
    c.time = l ? t(l.ts) : t(c.ts);
  }

  // Informational and diagnostic leaves.
  let prevTs: number | null = null;
  for (const l of s.leaves) {
    if (l.kind === 'outcome_uncertain') r.uncertainOutcomes++;
    if (l.kind === 'clock_regression') r.clockRegressions.leafLeaves++;
    if (l.kind === 'key_revocation' && typeof l.body?.kid === 'string') r.informationalRevocations.push({ kid: l.body.kid, compromisedSince: String(l.body.compromisedSince) });
    const ts = t(l.ts);
    if (ts !== null && prevTs !== null && ts < prevTs - 60_000) r.clockRegressions.observed++;
    if (ts !== null) prevTs = ts;
  }
  if (r.informationalRevocations.length) r.warnings.push('key_revocation leaves are informational: authority comes only from the trust anchor (revokedSince)');
  void warnings;

  r.outcome = r.broken.length ? 'broken' : r.conflicts.length ? 'conflicting_history' : 'consistent';
}

// ── Retained checkpoints ─────────────────────────────────────────────────────────────────────────────────────────────────────
interface Retained { segmentId: string; size: number; root: Buffer; entry: RetainedEntry }

function collectRetained(opts: VerifyOptions, keyName: string | null, keys: Map<string, KeyInfo>, trust: { trusted: Map<string, string>; revokedAt: (fp: string, t: number | null) => boolean } | null, warnings: string[]): Retained[] {
  const out: Retained[] = [];
  for (const e of [...(opts.retained ?? []), ...(opts.trust?.retainedCheckpoints ?? [])]) {
    try {
      const note = parseNote(e.note);
      if (!keyName || !note.origin.startsWith(`${keyName}/`)) { warnings.push('a retained checkpoint belongs to another installation; ignored'); continue; }
      const segmentId = note.origin.slice(`${keyName}/`.length);
      const name = keyName;
      const candidates: Buffer[] = e.publicKey ? [Buffer.from(e.publicKey, 'base64')] : [];
      for (const k of keys.values()) candidates.push(k.publicKey);
      let signer: Buffer | null = null;
      for (const sg of note.sigs) for (const pub of candidates) {
        if (sg.name === name && pub.length === 32 && c2spKeyHash(name, pub).equals(sg.keyHash) && ed25519Ok(pub, Buffer.from(note.body, 'utf8'), sg.sig)) signer = pub;
      }
      if (!signer) { warnings.push(`a retained checkpoint (size ${note.size}) has no valid signature by a known key; ignored`); continue; }
      const fp = fingerprintOf(signer);
      if (trust) {
        if (!trust.trusted.has(fp) || trust.revokedAt(fp, t(e.ts))) { warnings.push(`a retained checkpoint (size ${note.size}) is signed by a key that is not trusted by the anchor; ignored`); continue; }
      } else if (![...keys.values()].some((k) => k.fingerprint === fp)) { warnings.push(`a retained checkpoint (size ${note.size}) is signed by a key not in the export's key history and there is no anchor; ignored`); continue; }
      if (note.size !== e.size || note.root.toString('hex') !== e.rootHash) { warnings.push('a retained checkpoint record does not match its note; ignored'); continue; }
      out.push({ segmentId, size: note.size, root: note.root, entry: e });
    } catch (err) { warnings.push(`a retained checkpoint is malformed (${(err as Error).message}); ignored`); }
  }
  return out;
}

type Relation = 'match' | 'conflict' | 'unrelated' | 'ahead';

function relate(s: SegData, m: number, root: Buffer): Relation {
  const cp = s.cps.find((c) => c.size === m);
  if (cp) return cp.root.equals(root) ? 'match' : 'conflict';
  const direct = s.rootAt.get(m);
  if (direct) return direct.equals(root) ? 'match' : 'conflict';
  if (m > s.n) return 'ahead';
  const cuts: any[] = Array.isArray(s.proofs?.retention) ? s.proofs.retention : [];
  for (const cut of cuts) {
    const pf = Array.isArray(cut.proofs) ? cut.proofs.find((p: any) => Number(p.from) === m) : null;
    if (pf && Number(cut.cutSize) > m) {
      const rk = Peaks.from(Number(cut.cutSize), (cut.compactRange as string[]).map(hexBuf)).root();
      return checkConsistency(m, Number(cut.cutSize), root, rk, pf.proof.map(hexBuf)) ? 'match' : 'conflict';
    }
  }
  return 'unrelated';
}

function applyRetained(s: SegData, rs: Retained[]): void {
  const r = s.analysis;
  let unrelated = 0;
  const aheadLinked: Retained[] = [];
  const bySize = new Map(rs.map((x) => [x.size, x] as const));
  // Is a chain of retained entries anchored to this export's history? 'match' | 'conflict' | 'unlinked'.
  const link = (e: Retained, seen: Set<number>): 'match' | 'conflict' | 'unlinked' => {
    if (seen.has(e.size)) return 'unlinked';
    seen.add(e.size);
    const prev = e.entry.prev;
    if (!prev || !isHash(prev.rootHash) || !Array.isArray(prev.proof) || !prev.proof.every(isHash)) return 'unlinked';
    if (!checkConsistency(prev.size, e.size, hexBuf(prev.rootHash), e.root, prev.proof.map(hexBuf))) { r.warnings.push(`the retained file's proof from size ${prev.size} to ${e.size} does not verify; ignored`); return 'unlinked'; }
    if (prev.size <= s.n) {
      const rel = relate(s, prev.size, hexBuf(prev.rootHash));
      return rel === 'match' ? 'match' : rel === 'conflict' ? 'conflict' : 'unlinked';
    }
    const earlier = bySize.get(prev.size);
    return earlier && earlier.root.toString('hex') === prev.rootHash ? link(earlier, seen) : 'unlinked';
  };
  for (const e of rs) {
    const rel = relate(s, e.size, e.root);
    if (rel === 'conflict') r.conflicts.push(`a retained checkpoint of size ${e.size} commits to a different root than this export at that size`);
    else if (rel === 'unrelated') unrelated++;
    else if (rel === 'ahead') {
      const l = link(e, new Set());
      if (l === 'match') aheadLinked.push(e);
      else if (l === 'conflict') r.conflicts.push(`a retained checkpoint of size ${e.size} extends a history that differs from this export`);
      else unrelated++;
    }
  }
  if (unrelated) { r.qualifiers.push('retained_unrelated'); r.warnings.push(`${unrelated} retained checkpoint(s) could not be related to this export (not included, or no proof links them)`); }
  if (aheadLinked.length && !r.broken.length && !r.conflicts.length) {
    const top = aheadLinked.reduce((x, y) => (y.size > x.size ? y : x));
    r.rolledBack = { retainedSize: top.size, exportSize: s.n, unavailable: [s.n, top.size - 1] };
  }
  r.outcome = r.broken.length ? 'broken' : r.conflicts.length ? 'conflicting_history' : r.rolledBack ? 'rolled_back' : 'consistent';
}

// ── Provenance ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
function provenanceOf(s: SegData, trust: { trusted: Map<string, string>; revokedAt: (fp: string, t: number | null) => boolean; pins: Map<string, { revokedSince: number | null; revokedSinceText: string | null }> } | null, keys: Map<string, KeyInfo>): void {
  const r = s.analysis;
  if (!trust) {
    r.provenance = 'not_authenticated';
    r.provenanceDetail = 'no trust anchor supplied: signatures are valid against the key history inside the export, which proves nothing about whose key it is';
  } else {
    const checked = s.cps.filter((c) => c.verified && c.sigValid);
    const untrusted = checked.filter((c) => !trust.trusted.has(c.fingerprint));
    const revoked = checked.filter((c) => trust.trusted.has(c.fingerprint) && trust.revokedAt(c.fingerprint, c.time));
    if (!checked.length) { r.provenance = 'not_authenticated'; r.provenanceDetail = 'no verified signed checkpoint in this segment'; }
    else if (revoked.length) {
      const fp = revoked[0]!.fingerprint;
      r.provenance = 'revoked';
      r.provenanceDetail = `${revoked.length} checkpoint(s) signed by key ${[...keys.values()].find((k) => k.fingerprint === fp)?.kid ?? fp.slice(0, 8)} at or after the revocation time in the trust anchor (revoked since ${trust.pins.get(fp)?.revokedSinceText})`;
    } else if (untrusted.length) {
      r.provenance = 'not_authenticated';
      r.provenanceDetail = `${untrusted.length} checkpoint(s) signed by keys the trust anchor does not trust or extend through a rotation (${[...new Set(untrusted.map((c) => c.kid))].join(', ')})`;
    } else { r.provenance = 'authenticated'; r.provenanceDetail = 'every checkpoint is signed by a key pinned in the trust anchor or extended through a rotation statement made while its predecessor was trusted'; }
  }
  r.verified = r.outcome === 'consistent' && r.provenance === 'authenticated' && !r.qualifiers.includes('retained_unrelated') && !r.qualifiers.includes('no_checkpoint');
}
