// Merkle tree logic for signed, append-only evidence logs, implemented from RFC 6962 / RFC 9162 and the
// format specification (docs/verify-log-format.md). It shares no code with any producer of such logs, so that
// a bug in a producer is not silently a bug here. Only node:crypto SHA-256 is used.
import { createHash } from 'node:crypto';

const H = (...p: Buffer[]): Buffer => { const h = createHash('sha256'); p.forEach((x) => h.update(x)); return h.digest(); };

export const EMPTY_ROOT = H();
export const nodeHash = (l: Buffer, r: Buffer): Buffer => H(Buffer.from([1]), l, r);
export const leafHashOf = (jcsBytes: Buffer): Buffer => H(Buffer.from([0]), jcsBytes);

// Largest power of two strictly below n (n >= 2).
export function splitPoint(n: number): number { let k = 1; while (k << 1 < n) k <<= 1; return k; }

/** Reference tree hash, straight from the RFC definition. */
export function mth(d: Buffer[]): Buffer {
  if (d.length === 0) return EMPTY_ROOT;
  if (d.length === 1) return d[0]!;
  const k = splitPoint(d.length);
  return nodeHash(mth(d.slice(0, k)), mth(d.slice(k)));
}

/** Reference inclusion path (RFC 9162 2.1.3.1). */
export function inclusionPath(m: number, d: Buffer[]): Buffer[] {
  if (d.length <= 1) return [];
  const k = splitPoint(d.length);
  return m < k ? [...inclusionPath(m, d.slice(0, k)), mth(d.slice(k))] : [...inclusionPath(m - k, d.slice(k)), mth(d.slice(0, k))];
}

/** Reference consistency proof (RFC 9162 2.1.4.1). */
export function consistencyPath(m: number, d: Buffer[]): Buffer[] {
  if (m === 0 || m === d.length) return [];
  const sub = (mm: number, dd: Buffer[], top: boolean): Buffer[] => {
    if (mm === dd.length) return top ? [] : [mth(dd)];
    const k = splitPoint(dd.length);
    return mm <= k ? [...sub(mm, dd.slice(0, k), top), mth(dd.slice(k))] : [...sub(mm - k, dd.slice(k), false), mth(dd.slice(0, k))];
  };
  return sub(m, d, true);
}

/** RFC 9162 2.1.3.2. */
export function checkInclusion(idx: number, size: number, leaf: Buffer, path: Buffer[], root: Buffer): boolean {
  if (idx >= size || idx < 0) return false;
  let fn = idx, sn = size - 1, r = leaf;
  for (const p of path) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else r = nodeHash(r, p);
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && r.equals(root);
}

/** RFC 9162 2.1.4.2. */
export function checkConsistency(m: number, n: number, rootM: Buffer, rootN: Buffer, path: Buffer[]): boolean {
  if (m > n || m < 0) return false;
  if (m === n) return path.length === 0 && rootM.equals(rootN);
  if (m === 0) return path.length === 0;
  const p = (m & (m - 1)) === 0 ? [rootM, ...path] : path;
  if (!p.length) return false;
  let fn = m - 1, sn = n - 1;
  while (fn % 2 === 1) { fn >>= 1; sn >>= 1; }
  let fr = p[0]!, sr = p[0]!;
  for (let i = 1; i < p.length; i++) {
    const c = p[i]!;
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(c, fr); sr = nodeHash(c, sr);
      while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else sr = nodeHash(sr, c);
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && fr.equals(rootM) && sr.equals(rootN);
}

/** Set bits of `size`, high to low: the levels of the perfect subtrees covering [0, size). */
export function levelsOf(size: number): number[] {
  const out: number[] = [];
  for (let b = 52; b >= 0; b--) if (Math.floor(size / 2 ** b) % 2) out.push(b);
  return out;
}

/** Minimal aligned decomposition of [begin, end), left to right. */
export function decompose(begin: number, end: number): { level: number; pos: number }[] {
  const out: { level: number; pos: number }[] = [];
  for (let pos = begin; pos < end;) {
    let level = 0;
    while (pos % 2 ** (level + 1) === 0 && pos + 2 ** (level + 1) <= end) level++;
    out.push({ level, pos });
    pos += 2 ** level;
  }
  return out;
}

/** The peaks of [0, size) with a way to append leaves and aligned subtrees, and to read the root. */
export class Peaks {
  private stack: { h: Buffer; level: number }[] = [];
  size = 0;
  static from(size: number, hashes: Buffer[]): Peaks {
    const lv = levelsOf(size);
    if (lv.length !== hashes.length) throw new Error('compact range length does not match its size');
    const p = new Peaks();
    p.stack = lv.map((level, i) => ({ h: hashes[i]!, level }));
    p.size = size;
    return p;
  }
  push(h: Buffer, level: number): void {
    if (this.size % 2 ** level !== 0) throw new Error('misaligned subtree');
    this.size += 2 ** level;
    let cur = h, lvl = level;
    for (let top = this.stack[this.stack.length - 1]; top && top.level === lvl; top = this.stack[this.stack.length - 1]) { this.stack.pop(); cur = nodeHash(top.h, cur); lvl++; }
    this.stack.push({ h: cur, level: lvl });
  }
  root(): Buffer {
    if (!this.stack.length) return EMPTY_ROOT;
    return this.stack.reduceRight((acc, e, i, all) => (i === all.length - 1 ? e.h : nodeHash(e.h, acc)), EMPTY_ROOT);
  }
}

/** root(n) from the compact range of [0,a), leaves [a,b) and the compact range of [b,n). */
export function foldParts(a: number, left: Buffer[], leaves: Buffer[], n: number, right: Buffer[]): Buffer {
  const p = Peaks.from(a, left);
  leaves.forEach((l) => p.push(l, 0));
  const nodes = decompose(a + leaves.length, n);
  if (nodes.length !== right.length) throw new Error('right compact range length does not match');
  nodes.forEach((d, i) => p.push(right[i]!, d.level));
  return p.root();
}
