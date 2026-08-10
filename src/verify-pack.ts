// `maindala verify-pack <dir>` — offline verifier for mAIndala Compliance
// Evidence Packs. Deliberately duplicates the platform's own evidence-pack
// verification logic rather than sharing a package: this CLI is published
// standalone to npm, and RFC 3161 verification is a small, stable,
// standards-based algorithm unlikely to change.
import { existsSync, readFileSync, lstatSync } from 'node:fs';
import { join } from 'node:path';
import crypto, { webcrypto } from 'node:crypto';
import * as pkijs from 'pkijs';
import { resolveWithinRoot, assertFlatSegment } from './safe-path.js';

function sha256Hex(content: Buffer): string {
  return `sha256:${crypto.createHash('sha256').update(content).digest('hex')}`;
}

// FreeTSA's published Root CA certificate (https://www.freetsa.org/files/cacert.pem) —
// pinned in source so verification works fully offline, years later, no network call.
const FREETSA_ROOT_CA_PEM = `-----BEGIN CERTIFICATE-----
MIIH/zCCBeegAwIBAgIJAMHphhYNqOmAMA0GCSqGSIb3DQEBDQUAMIGVMREwDwYD
VQQKEwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZy
ZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIw
EAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREUw
HhcNMTYwMzEzMDE1MjEzWhcNNDEwMzA3MDE1MjEzWjCBlTERMA8GA1UEChMIRnJl
ZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9y
ZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJ
V3VlcnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtgKODjAy8REQ2WTNqUudAnjhlCrpE6ql
mQfNppeTmVvZrH4zutn+NwTaHAGpjSGv4/WRpZ1wZ3BRZ5mPUBZyLgq0YrIfQ5Fx
0s/MRZPzc1r3lKWrMR9sAQx4mN4z11xFEO529L0dFJjPF9MD8Gpd2feWzGyptlel
b+PqT+++fOa2oY0+NaMM7l/xcNHPOaMz0/2olk0i22hbKeVhvokPCqhFhzsuhKsm
q4Of/o+t6dI7sx5h0nPMm4gGSRhfq+z6BTRgCrqQG2FOLoVFgt6iIm/BnNffUr7V
DYd3zZmIwFOj/H3DKHoGik/xK3E82YA2ZulVOFRW/zj4ApjPa5OFbpIkd0pmzxzd
EcL479hSA9dFiyVmSxPtY5ze1P+BE9bMU1PScpRzw8MHFXxyKqW13Qv7LWw4sbk3
SciB7GACbQiVGzgkvXG6y85HOuvWNvC5GLSiyP9GlPB0V68tbxz4JVTRdw/Xn/XT
FNzRBM3cq8lBOAVt/PAX5+uFcv1S9wFE8YjaBfWCP1jdBil+c4e+0tdywT2oJmYB
BF/kEt1wmGwMmHunNEuQNzh1FtJY54hbUfiWi38mASE7xMtMhfj/C4SvapiDN837
gYaPfs8x3KZxbX7C3YAsFnJinlwAUss1fdKar8Q/YVs7H/nU4c4Ixxxz4f67fcVq
M2ITKentbCMCAwEAAaOCAk4wggJKMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQD
AgHGMB0GA1UdDgQWBBT6VQ2MNGZRQ0z357OnbJWveuaklzCBygYDVR0jBIHCMIG/
gBT6VQ2MNGZRQ0z357OnbJWveuaklzCBm6SBmDCBlTERMA8GA1UEChMIRnJlZSBU
U0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9yZzEi
MCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJV3Vl
cnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFggkAwemGFg2o6YAw
MwYDVR0fBCwwKjAooCagJIYiaHR0cDovL3d3dy5mcmVldHNhLm9yZy9yb290X2Nh
LmNybDCBzwYDVR0gBIHHMIHEMIHBBgorBgEEAYHyJAEBMIGyMDMGCCsGAQUFBwIB
FidodHRwOi8vd3d3LmZyZWV0c2Eub3JnL2ZyZWV0c2FfY3BzLmh0bWwwMgYIKwYB
BQUHAgEWJmh0dHA6Ly93d3cuZnJlZXRzYS5vcmcvZnJlZXRzYV9jcHMucGRmMEcG
CCsGAQUFBwICMDsaOUZyZWVUU0EgdHJ1c3RlZCB0aW1lc3RhbXBpbmcgU29mdHdh
cmUgYXMgYSBTZXJ2aWNlIChTYWFTKTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUH
MAGGG2h0dHA6Ly93d3cuZnJlZXRzYS5vcmc6MjU2MDANBgkqhkiG9w0BAQ0FAAOC
AgEAaK9+v5OFYu9M6ztYC+L69sw1omdyli89lZAfpWMMh9CRmJhM6KBqM/ipwoLt
nxyxGsbCPhcQjuTvzm+ylN6VwTMmIlVyVSLKYZcdSjt/eCUN+41K7sD7GVmxZBAF
ILnBDmTGJmLkrU0KuuIpj8lI/E6Z6NnmuP2+RAQSHsfBQi6sssnXMo4HOW5gtPO7
gDrUpVXID++1P4XndkoKn7Svw5n0zS9fv1hxBcYIHPPQUze2u30bAQt0n0iIyRLz
aWuhtpAtd7ffwEbASgzB7E+NGF4tpV37e8KiA2xiGSRqT5ndu28fgpOY87gD3ArZ
DctZvvTCfHdAS5kEO3gnGGeZEVLDmfEsv8TGJa3AljVa5E40IQDsUXpQLi8G+UC4
1DWZu8EVT4rnYaCw1VX7ShOR1PNCCvjb8S8tfdudd9zhU3gEB0rxdeTy1tVbNLXW
99y90xcwr1ZIDUwM/xQ/noO8FRhm0LoPC73Ef+J4ZBdrvWwauF3zJe33d4ibxEcb
8/pz5WzFkeixYM2nsHhqHsBKw7JPouKNXRnl5IAE1eFmqDyC7G/VT7OF669xM6hb
Ut5G21JE4cNK6NNucS+fzg1JPX0+3VhsYZjj7D5uljRvQXrJ8iHgr/M6j2oLHvTA
I2MLdq2qjZFDOCXsxBxJpbmLGBx9ow6ZerlUxzws2AWv2pk=
-----END CERTIFICATE-----`;

function pemToDer(pem: string): Buffer {
  const b64 = pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s/g, '');
  return Buffer.from(b64, 'base64');
}

let engineReady = false;
function ensureEngine(): void {
  if (engineReady) return;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  pkijs.setEngine('node-webcrypto', new pkijs.CryptoEngine({ name: 'node', crypto: webcrypto as any }));
  engineReady = true;
}

async function verifyTimestampToken(tokenDer: Buffer, originalData: Buffer): Promise<boolean> {
  try {
    ensureEngine();
    const contentInfo = pkijs.ContentInfo.fromBER(tokenDer);
    const signedData = new pkijs.SignedData({ schema: contentInfo.content });
    const data = Uint8Array.from(originalData).buffer as ArrayBuffer;
    return await signedData.verify({
      signer: 0,
      checkChain: true,
      trustedCerts: [pkijs.Certificate.fromBER(pemToDer(FREETSA_ROOT_CA_PEM))],
      data,
    });
  } catch {
    return false;
  }
}

interface ManifestSection {
  name: string;
  digest: string;
  rowCount?: number;
}

export interface VerifyPackResult {
  ok: boolean;
  exitCode: 0 | 1 | 2;
  lines: string[];
}

// Core verification logic — exported for testability, called by the CLI action below.
export async function verifyPack(dir: string): Promise<VerifyPackResult> {
  const lines: string[] = [];
  const manifestPath = join(dir, 'manifest.json');
  if (!existsSync(manifestPath)) {
    return { ok: false, exitCode: 2, lines: [`manifest.json not found in ${dir}`] };
  }

  const manifestBytes = readFileSync(manifestPath);
  let manifest: { sections?: ManifestSection[] };
  try {
    manifest = JSON.parse(manifestBytes.toString('utf-8'));
  } catch {
    return { ok: false, exitCode: 1, lines: ['manifest.json is not valid JSON — the pack is not usable'] };
  }

  const sections = manifest.sections ?? [];
  if (sections.length === 0) {
    return { ok: false, exitCode: 1, lines: ['manifest.json has no sections list — malformed or unsupported pack format'] };
  }

  let allOk = true;
  lines.push(`Checking ${sections.length} section(s) against manifest.json...`);
  for (const section of sections) {
    // section.name comes from the pack being verified, i.e. from whoever
    // produced or handed you this pack — it is untrusted input by
    // definition (verifying an untrusted pack is the entire point of this
    // command). Evidence-pack sections are defined as flat filenames, so
    // reject anything containing a path separator before touching the
    // filesystem, then confine the resolved path to `dir` as defense in
    // depth.
    try {
      assertFlatSegment(section.name, 'section name');
    } catch {
      lines.push(`  ✗ ${section.name}: invalid section name (path separators are not allowed)`);
      allOk = false;
      continue;
    }
    let filePath: string;
    try {
      filePath = resolveWithinRoot(dir, section.name);
    } catch {
      lines.push(`  ✗ ${section.name}: invalid section name (resolves outside the pack directory)`);
      allOk = false;
      continue;
    }
    if (!existsSync(filePath)) {
      lines.push(`  ✗ ${section.name}: file missing`);
      allOk = false;
      continue;
    }
    // Reject symlinks and anything else that isn't a plain file — a symlink
    // section could otherwise redirect a "contained" read to an arbitrary
    // target the confinement check never sees, since it only validates the
    // symlink's own path, not what it points to.
    const stat = lstatSync(filePath);
    if (stat.isSymbolicLink() || !stat.isFile()) {
      lines.push(`  ✗ ${section.name}: not a regular file (symlinks are rejected)`);
      allOk = false;
      continue;
    }
    const actualDigest = sha256Hex(readFileSync(filePath));
    if (actualDigest !== section.digest) {
      // Deliberately do NOT include actualDigest here. Printing the
      // recomputed digest of an attacker-influenced path would let a
      // crafted section.name be used to confirm the exact contents of an
      // arbitrary file — the digest itself is the exfiltration primitive,
      // independent of whether the path was ever successfully confined.
      lines.push(`  ✗ ${section.name}: digest mismatch`);
      allOk = false;
    } else {
      lines.push(`  ✓ ${section.name}`);
    }
  }

  const recomputedPackDigest = sha256Hex(manifestBytes);
  lines.push('', `Recomputed pack digest (sha256 of manifest.json): ${recomputedPackDigest}`);

  const tstPath = join(dir, 'timestamp.tsr');
  let tstValid: boolean | undefined;
  if (existsSync(tstPath)) {
    tstValid = await verifyTimestampToken(readFileSync(tstPath), manifestBytes);
    lines.push('', `RFC 3161 timestamp: ${tstValid ? 'VALID' : 'INVALID'}`);
  } else {
    lines.push('', 'No timestamp.tsr found — self-consistency check only.');
  }

  const ok = allOk && tstValid !== false;
  lines.push('', `Result: ${ok ? 'INTACT' : 'TAMPERED OR INCOMPLETE'}`);
  return { ok, exitCode: ok ? 0 : 1, lines };
}
