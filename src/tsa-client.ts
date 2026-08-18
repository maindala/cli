// RFC 3161 timestamp client for `maindala scan --timestamp` — ported from the
// catalog-service evidence-pack TSA client (same technique, same library set,
// which is why @peculiar/asn1-* and pkijs are already dependencies of this
// CLI, used today only for verify-pack.ts's token *verification*). Submits
// the scan manifest's own digest to a public Time-Stamp Authority so the
// customer's local record carries a third-party-anchored timestamp without
// mAIndala retaining anything. Never throws — a failed or unreachable TSA
// degrades to no timestamp, matching this CLI's "never block on network
// reachability" posture for the report itself.

import crypto from 'node:crypto';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import { MessageImprint, TimeStampReq, TimeStampReqVersion, TimeStampResp } from '@peculiar/asn1-tsp';
import { AlgorithmIdentifier } from '@peculiar/asn1-x509';

const SHA256_OID = '2.16.840.1.101.3.4.2.1';
const TIMEOUT_MS = 5_000;
export const DEFAULT_TSA_URL = 'https://freetsa.org/tsr';

function getTsaUrl(): string {
  return process.env['MAINDALA_TSA_URL'] ?? DEFAULT_TSA_URL;
}

function toArrayBuffer(buf: Buffer | Uint8Array): ArrayBuffer {
  return Uint8Array.from(buf).buffer as ArrayBuffer;
}

function randomPositiveNonce(): ArrayBuffer {
  const bytes = crypto.randomBytes(8);
  bytes[0]! &= 0x7f; // ASN.1 INTEGER must be positive — clear the sign bit
  return toArrayBuffer(bytes);
}

// digest: the raw SHA-256 digest bytes of the artifact being timestamped
// (the same bytes recorded as the manifest's own `digest` field, decoded
// from hex — not the hex string itself). Returns null on any failure.
export async function requestTimestamp(digest: Buffer): Promise<Buffer | null> {
  const tsaUrl = getTsaUrl();
  try {
    const req = new TimeStampReq({
      version: TimeStampReqVersion.v1,
      messageImprint: new MessageImprint({
        hashAlgorithm: new AlgorithmIdentifier({ algorithm: SHA256_OID, parameters: null }),
        hashedMessage: new OctetString(toArrayBuffer(digest)),
      }),
      nonce: randomPositiveNonce(),
      certReq: true,
    });
    const reqDer = Buffer.from(AsnConvert.serialize(req));

    const res = await fetch(tsaUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/timestamp-query' },
      body: reqDer,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return null;

    const respBytes = Buffer.from(await res.arrayBuffer());
    const parsed = AsnConvert.parse(respBytes, TimeStampResp);
    if (parsed.status.status !== 0 || !parsed.timeStampToken) return null; // 0 = granted

    return Buffer.from(AsnConvert.serialize(parsed.timeStampToken));
  } catch {
    return null;
  }
}
