# Signed evidence log exports (format version 1)

`maindala verify-log <exportDir>` checks, offline, an export of a signed, append-only evidence log. This document describes
what such an export contains and exactly what the verifier checks, so the format can be implemented or audited independently.
The verifier uses Node's built-in crypto only and makes no network call.

```
maindala verify-log <exportDir> [--trust trust.json] [--retained checkpoints.ndjson] [--json]
```

## 1. Leaves

The log is a sequence of **leaves**, one per recorded event. A leaf is the JSON object
`{"kind": <string>, "ts": <RFC 3339 UTC timestamp>, "body": <object>}`. Its bytes are the RFC 8785 (JCS) canonical form of that
object, encoded as UTF-8.

* Leaf hash: `SHA-256(0x00 || JCS(leaf))`
* Interior node: `SHA-256(0x01 || left || right)`
* Empty tree: `SHA-256("")`

The verifier gives meaning to a handful of `kind` values and treats every other kind as opaque data:

| kind | what the verifier does with it |
|---|---|
| `segment_start` | leaf 0 of a segment; its `previousSegmentId` / `previousCheckpoint` / `reason` / `reasonText` describe a recovery link |
| `key_rotation` | may extend trust to a new key (section 6) |
| `key_revocation` | reported as informational; never changes trust |
| `retention_cut` | cross-checked against the cut record in `proofs.json` (section 5) |
| `outcome_uncertain`, `clock_regression` | counted and reported as warnings |

## 2. Tree

Each **segment** is one append-only Merkle tree as defined in RFC 6962 / RFC 9162: for `n` leaves, split at `k`, the largest power of
two strictly below `n`, and hash the two halves. Consistency proofs are the RFC 9162 section 2.1.4 proofs and are checked with the
algorithm given there. The implementation is tested against the published transparency-dev test vectors and against a naive recursive
tree hash for every size in a range.

A **compact range** of `[a, b)` is the list of roots of the minimal aligned perfect subtrees covering it, left to right. An export of
leaves `[a, b)` from a tree that has `n` leaves carries the compact range of `[0, a)` and of `[b, n)`; folding
`left + leaves[a..b) + right` must give the root at size `n`.

## 3. Checkpoints

A checkpoint is a [C2SP signed note](https://c2sp.org/signed-note) holding a [tlog-checkpoint](https://c2sp.org/tlog-checkpoint) body.
Each line of the body ends in LF:

```
<origin>
<tree size, canonical decimal>
<root hash, base64 of 32 bytes>
```

followed by one blank line and one line per signature, `— <name> <base64(4-byte key hash || 64-byte Ed25519 signature)>` (an em
dash, then a space). The signature is over the body bytes.

**Origin and key name.** The origin is `<prefix>/<installationId>/<segmentId>` and the signer name is `<prefix>/<installationId>`.
The `<prefix>` is chosen by whoever produces the log and is opaque to the verifier. The verifier requires only that

* the export's `key-history.json` declares `keyName` as exactly `<prefix>/<installationId>` (where `installationId` is the export's own
  installation id; the prefix is non-empty and has no whitespace),
* every checkpoint origin is that key name followed by `/` and the segment id of the segment the checkpoint belongs to,
* every signature uses that same name.

The prefix carries no authority: whether a key is believed comes only from the trust file (section 6).

The key hash is the first 4 bytes of `SHA-256(name || 0x0A || 0x01 || 32-byte raw Ed25519 public key)`. The key id (`kid`) is that
hash in lowercase hex. The key **fingerprint** is `SHA-256(raw public key)` in lowercase hex; trust files refer to keys by fingerprint.

A checkpoint carries no time. Where a time is needed (revocation, section 6) the verifier uses the timestamp of the last leaf the
checkpoint covers, falling back to the producer's unsigned record time if that leaf is not in the export. Leaves written after
the last checkpoint are the *unsigned tail*: a change to them before a checkpoint is signed cannot be detected by any verifier.

## 4. Export directory

| File | Content |
|---|---|
| `leaves.ndjson` | one JSON line per exported leaf: `{segmentId, index, kind, ts, body, leafHash}` |
| `checkpoints.ndjson` | `{segmentId, size, rootHash, kid, ts, note}` for stored checkpoints up to the target size |
| `proofs.json` | `{segments: {<id>: {targetSize, left:[hex], right:[hex], consistency:[{from,to,proof:[hex]}], retention:[{cutSize, compactRange:[hex], checkpoint:{size,rootHash,kid,ts,note}, proofs:[{from,proof:[hex]}]}]}}}` |
| `segment.json` | `{segments:[{segmentId, startedAt, reason, previousSegmentId, link, status, range:{from,to,targetSize}}]}` |
| `key-history.json` | `{installationId, keyName, keys:[{kid, publicKey (base64, raw), fingerprint}], events:[...]}`; public keys only |
| `manifest.json` | JCS object: `formatVersion`, `installationId`, `exportedAt`, `files {name: sha256 hex}`, and informational fields |
| `manifest.sig` | `{kid, signature}`: Ed25519 over the exact bytes of `manifest.json` |

`VERIFY.md` and `CONFIDENTIAL.txt` may also be present; if the manifest lists them their digests are checked. Every other file
must be listed in the manifest and match its digest. `formatVersion` is an integer (currently 1); a verifier refuses a higher one.

## 5. What is checked

* **Leaves:** exactly the declared range, no gaps or duplicates, and every `leafHash` recomputed from the leaf content.
* **Boundaries:** the left and right compact ranges have the right length and fold, with the leaves, to the target root.
* **Checkpoints:** notes parse, origins and signer names match (section 3), signatures verify against a key in the key history, the
  record agrees with its signed note, and each root is checked against the tree: directly where the leaves allow it, by a
  consistency proof to the target size, or (below a retention cut) by the stored proofs to the cut.
* **Retention cuts:** a cut's compact range must fold to the signed checkpoint at that size and to the cut leaf's root.
* **Manifest:** file digests and the manifest signature.
* **Retained checkpoints** (`--retained`, section 7): each is checked for a valid signature by a key that the trust file (or, without
  one, the key history) accepts, and related to the export.

### Outcomes

Per segment, structure (**outcome**) and identity (**provenance**) are reported separately.

| Outcome | Meaning |
|---|---|
| `consistent` | leaves recompute, boundaries fold to every checkpoint root that can be checked, signatures valid |
| `rolled_back` | consistent, but a retained checkpoint beyond the export links to it: history after the export's size is missing |
| `conflicting_history` | a retained (or second signed) checkpoint at some size commits to a different root, or extends a different history |
| `broken` | a missing, duplicate or altered leaf, a bad boundary, proof, note or signature, or a bad retention cut; the first failing index is reported, or else the range between the last good and the first bad checkpoint |

A `broken` segment stays `broken`: a later recovery segment is judged on its own merits and a warning notes that the earlier one
remains broken.

Qualifiers on a consistent outcome: `history_not_included` (positions outside the exported range or pruned by a cut),
`retained_unrelated` (a retained checkpoint could not be related to the export), `checkpoint_not_checked`, `no_checkpoint`.

| Provenance | Meaning |
|---|---|
| `authenticated` | every verified checkpoint is signed by a key pinned in the trust file, or reached through a valid rotation |
| `not_authenticated` | no trust file, or some signer is not trusted |
| `revoked` | a verified checkpoint is signed by a pinned key at or after its `revokedSince` time |

**Verified** means: outcome `consistent` and provenance `authenticated` for every segment, the manifest and its signature verify,
the manifest signer is trusted, and no qualifier leaves part of the history unrelated. Without a trust file nothing is ever
verified.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | verified |
| 1 | consistent but not (fully) authenticated, or rolled back, or not fully related |
| 2 | failed: broken or conflicting history, bad manifest or signature, a trust file for another installation, a trust file none of whose keys appears in the export, or an unreadable trust or retained file |

`--json` prints the complete report (every field above) and uses the same exit codes.

## 6. trust.json

The trust file comes from outside the export (for example, recorded when the log's producer was set up). Without it the verifier can
prove only that the export is internally consistent, not whose it is.

```json
{
  "installationId": "<the export's installationId>",
  "pinnedKeys": [
    { "fingerprint": "<sha-256 of the raw public key, hex>", "kid": "<optional>", "pinnedAt": "<optional>", "revokedSince": "<optional RFC 3339 time>" }
  ],
  "retainedCheckpoints": [ "<optional: entries in the --retained format>" ]
}
```

* The `installationId` must equal the export's, and at least one pinned key must appear in the export's key history; otherwise
  verification fails (exit 2).
* **Rotation.** A `key_rotation` leaf (`oldFingerprint`, `newPublicKey`, `newKid`, `newFingerprint`) extends trust to the new key only
  if a verified checkpoint covering that leaf was signed by the old key, the old key is already trusted, and the old key was not
  revoked (per `revokedSince`) at the leaf's time or the checkpoint's time. A new key is otherwise not trusted until pinned.
* **Revocation.** `revokedSince` is authoritative only in this file. A `key_revocation` leaf inside the log is informational.

**Limitation: revocation time.** Checkpoints carry no time of their own, so `revokedSince` is judged against timestamps the log's
producer wrote into its leaves. Someone who holds a compromised key can write leaves and checkpoints with any timestamp, including ones
earlier than `revokedSince`, and the time check will not catch that. Only something the key holder does not control bounds it:
a checkpoint retained independently from before the compromise (history that does not extend it is reported as conflicting), or an
external timestamp or witness. Do not treat `revokedSince` alone as protection against a holder of the compromised key.

## 7. Retained checkpoints

`--retained` takes an NDJSON file, one entry per line:
`{segmentId, size, rootHash, kid, ts, note, publicKey, prev: {size, rootHash, proof:[hex]} | null}`. `prev` links an entry to the
checkpoint before it with a consistency proof, which lets the verifier relate a retained checkpoint *beyond* the export's size to the
exported history. An entry whose origin names another installation, or whose signature no accepted key makes, is ignored with a
warning. Checkpoints kept somewhere the log's producer cannot rewrite are what turn "consistent" into "not rolled back and not
rewritten".

## 8. Limits

The tree code is tested to hundreds of leaves, not billions. The unsigned tail (section 3) is undetectable. Someone holding the
signing key who can also rewrite every retained copy of every checkpoint can forge history. Times are those of the producer's clock.
A valid log shows what the signing key signed, not that any recorded call reached its target or that no call bypassed the recorder.
