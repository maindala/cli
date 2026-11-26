// Checkpoint notes (C2SP signed note carrying a tlog-checkpoint body), parsed and checked from the specification.
import { createHash, createPublicKey, verify } from 'node:crypto';

export interface Note { origin: string; size: number; root: Buffer; body: string; sigs: { name: string; keyHash: Buffer; sig: Buffer }[] }

// Parses a note; throws a descriptive error for any malformed part.
export function parseNote(text: string): Note {
  const cut = text.indexOf('\n\n');
  if (cut < 0 || !text.endsWith('\n')) throw new Error('no signature block');
  const body = text.slice(0, cut + 1);
  const lines = body.split('\n');
  if (lines.length < 4) throw new Error('checkpoint body has fewer than three lines');
  if (!/^(0|[1-9][0-9]*)$/.test(lines[1]!)) throw new Error('size is not a canonical decimal');
  const root = Buffer.from(lines[2]!, 'base64');
  if (root.length !== 32 || root.toString('base64') !== lines[2]) throw new Error('root is not 32 bytes of canonical base64');
  const sigs = text.slice(cut + 2).split('\n').filter((l) => l.length).map((l) => {
    const m = /^— (\S+) (\S+)$/.exec(l);
    if (!m) throw new Error('malformed signature line');
    const raw = Buffer.from(m[2]!, 'base64');
    if (raw.length !== 68) throw new Error('signature blob is not 4 + 64 bytes');
    return { name: m[1]!, keyHash: raw.subarray(0, 4), sig: raw.subarray(4) };
  });
  return { origin: lines[0]!, size: Number(lines[1]), root, body, sigs };
}

// C2SP key hash: first 4 bytes of SHA-256(name || LF || 0x01 || public key).
export const c2spKeyHash = (name: string, pub: Buffer): Buffer => createHash('sha256').update(name, 'utf8').update(Buffer.from([10, 1])).update(pub).digest().subarray(0, 4);

export const fingerprintOf = (pub: Buffer): string => createHash('sha256').update(pub).digest('hex');

// Ed25519 verification against a raw 32-byte key.
export function ed25519Ok(pub: Buffer, message: Buffer, sig: Buffer): boolean {
  try {
    return verify(null, message, createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pub]), format: 'der', type: 'spki' }), sig);
  } catch { return false; }
}
