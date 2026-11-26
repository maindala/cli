// `maindala verify-log <exportDir>` — renders verifyExport()'s report for a terminal or as JSON, and maps it to an exit code.
// Exit codes: 0 verified (consistent AND authenticated); 1 consistent but not authenticated (or rolled back / not fully related);
// 2 failed (broken, conflicting history, bad manifest or signature, wrong or unusable trust anchor, unreadable trust/retained file).
// Makes no network call.
import { readFileSync } from 'node:fs';
import { verifyExport, type RetainedEntry, type TrustFile } from './verify-log.js';

export interface VerifyLogCliOptions { trust?: string; retained?: string; json?: boolean }

/** Runs the verifier for the CLI; returns the lines to print and the process exit code. */
export function runVerifyLog(dir: string, o: VerifyLogCliOptions = {}): { lines: string[]; exitCode: 0 | 1 | 2 } {
  // ── Load the optional trust anchor and retained checkpoints ──
  let trust: TrustFile | undefined; let retained: RetainedEntry[] | undefined;
  try {
    if (o.trust) trust = JSON.parse(readFileSync(o.trust, 'utf8')) as TrustFile;
    if (o.retained) retained = readFileSync(o.retained, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l) as RetainedEntry);
  } catch (err) { return { lines: [`cannot read trust or retained file: ${(err as Error).message}`], exitCode: 2 }; }
  const report = verifyExport(dir, { ...(trust ? { trust } : {}), ...(retained ? { retained } : {}) });
  if (o.json) return { lines: [JSON.stringify(report, null, 2)], exitCode: report.exitCode };

  // ── Human-readable report ──
  const out: string[] = [];
  out.push(`installation ${report.installationId ?? '?'}  format ${report.formatVersion ?? '?'}`);
  out.push(`manifest: ${report.manifest.ok ? 'ok' : 'PROBLEMS'}${report.manifest.signedBy ? `  signed by ${report.manifest.signedBy.kid} (${report.manifest.signedBy.trusted ? 'trusted' : 'not trusted'})` : ''}`);
  for (const p of report.manifest.problems) out.push(`  - ${p}`);
  for (const s of report.segments) {
    out.push(`segment ${s.segmentId}: ${s.outcome.toUpperCase()}${s.qualifiers.length ? ` [${s.qualifiers.join(', ')}]` : ''}  provenance: ${s.provenance}  (${s.checkpoints} checkpoints, target ${s.targetSize}, leaves [${s.range.from}, ${s.range.to}))`);
    for (const h of s.historyNotIncluded) out.push(`  history not included: positions ${h.from}..${h.to - 1} (${h.reason})`);
    for (const b of s.broken) out.push(`  broken: ${b.detail}`);
    for (const c of s.conflicts) out.push(`  conflict: ${c}`);
    if (s.rolledBack) out.push(`  rolled back: a retained checkpoint covers ${s.rolledBack.retainedSize} leaves; positions ${s.rolledBack.unavailable[0]}..${s.rolledBack.unavailable[1]} are unavailable here`);
    if (s.uncertainOutcomes) out.push(`  ${s.uncertainOutcomes} outcome_uncertain leaf(s)`);
    if (s.recovery) out.push(`  follows segment ${s.recovery.previousSegmentId} (${s.recovery.reason}${s.recovery.reasonText ? `: ${s.recovery.reasonText}` : ''})`);
    for (const w of s.warnings) out.push(`  warning: ${w}`);
  }
  for (const w of report.warnings) out.push(`warning: ${w}`);
  for (const f of report.failures) out.push(`failure: ${f}`);
  out.push(report.summary);
  return { lines: out, exitCode: report.exitCode };
}
