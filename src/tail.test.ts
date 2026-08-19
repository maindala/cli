// Shadow AI Discovery P1 task 10 (SAD-11) — `maindala tail`'s alert event type. Unit tests
// against the pure mapping/rendering/cursor helpers rather than the org-scoped `tailActivity`
// polling loop itself (an unbounded `while (true)`, not a natural fit for a fast unit test) —
// these are the exact functions that carry the new alert-specific logic.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { toAlertTailEvent, renderLine, newestAlertRow, createBatchPrinter, type AlertRow } from './tail.js';

function makeAlert(overrides: Partial<AlertRow> = {}): AlertRow {
  return {
    id: 'alert-1', ruleId: 'R4', severity: 'critical', title: 'Deny burst detected',
    status: 'open', subjectName: 'My Agent', subjectId: 'agent-uuid-1234', occurrenceCount: 1,
    lastSeenAt: '2026-08-19T12:00:00.000Z', ...overrides,
  };
}

describe('toAlertTailEvent', () => {
  it('maps an alert row onto the shared TailEvent shape, reusing tool/target for ruleId/subject', () => {
    const e = toAlertTailEvent(makeAlert());
    expect(e.kind).toBe('alert');
    expect(e.tool).toBe('R4');
    expect(e.target).toBe('My Agent');
    expect(e.severity).toBe('critical');
    expect(e.status).toBe('open');
    expect(e.title).toBe('Deny burst detected');
    expect(e.occurrenceCount).toBe(1);
    expect(e.cursorId).toBe('alert-1');
    expect(e.decision).toBe(''); // alerts have no decision — status/severity carry the meaning instead
  });

  it('falls back to a truncated subjectId when subjectName is null (a subject kind other than external_agent, or one the join missed)', () => {
    const e = toAlertTailEvent(makeAlert({ subjectName: null, subjectId: 'abcdefgh-1111-2222-3333-444444444444' }));
    expect(e.target).toBe('abcdefgh');
  });
});

describe('renderLine — alert kind', () => {
  it('includes rule, subject, severity, title, and status; omits latency (alerts have none)', () => {
    const line = renderLine(toAlertTailEvent(makeAlert()));
    expect(line).toContain('[alert]');
    expect(line).toContain('R4 → My Agent');
    expect(line).toContain('critical');
    expect(line).toContain('Deny burst detected');
    expect(line).toContain('status=open');
  });

  it('shows an occurrence count only when it is greater than 1 — a single sighting is not "repeating"', () => {
    const once = renderLine(toAlertTailEvent(makeAlert({ occurrenceCount: 1 })));
    expect(once).not.toContain('×');
    const repeated = renderLine(toAlertTailEvent(makeAlert({ occurrenceCount: 3 })));
    expect(repeated).toContain('×3');
  });

  it('a tool_call/a2a_call line is unaffected — still renders latency and decision, no alert-specific fields', () => {
    const line = renderLine({
      kind: 'tool_call', ts: '2026-08-19T12:00:00.000Z', tool: 'search', target: 'github-mcp',
      decision: 'allow', latencyMs: 42, cursorId: 'x', cursorT: '2026-08-19T12:00:00.000Z',
    });
    expect(line).toContain('[tool]');
    expect(line).toContain('42ms');
    expect(line).toContain('allow');
  });
});

describe('createBatchPrinter — dedup (regression for a real bug caught live)', () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it('a repeat delivery of the SAME alert id with a bumped occurrenceCount is printed again, not silently swallowed', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const printBatch = createBatchPrinter({ json: true });

    printBatch([toAlertTailEvent(makeAlert({ occurrenceCount: 1 }))]);
    // Live-QA-caught bug: keying dedup on cursorId alone (matching tool_call/a2a_call, where
    // it's correct — those rows are immutable) silently ate every repeat-occurrence alert
    // after its first sighting, because the sweep's dedup pattern (task 5) means the SAME row
    // id legitimately reappears with a higher occurrenceCount, and SeenIds had already marked
    // that id seen. A real `maindala tail` run against a real backend showed only the first
    // sighting of a repeating alert, never the "still happening" follow-up — exactly what
    // SAD-11 asked this feature to surface.
    printBatch([toAlertTailEvent(makeAlert({ occurrenceCount: 2 }))]);

    expect(logSpy).toHaveBeenCalledTimes(2);
  });

  it('an exact repeat delivery (same id, same occurrenceCount — the inclusive >= cursor boundary re-fetching the identical row) is correctly suppressed', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const printBatch = createBatchPrinter({ json: true });

    printBatch([toAlertTailEvent(makeAlert({ occurrenceCount: 1 }))]);
    printBatch([toAlertTailEvent(makeAlert({ occurrenceCount: 1 }))]);

    expect(logSpy).toHaveBeenCalledTimes(1);
  });

  it('an unchanged tool_call id is still deduped exactly as before — this fix must not regress the existing immutable-row behavior', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const printBatch = createBatchPrinter({ json: true });
    const event = {
      kind: 'tool_call' as const, ts: '2026-08-19T12:00:00.000Z', tool: 'search', target: 'github-mcp',
      decision: 'allow', latencyMs: 42, cursorId: 'call-1', cursorT: '2026-08-19T12:00:00.000Z',
    };

    printBatch([event]);
    printBatch([event]); // the inclusive >= cursor boundary can legitimately re-deliver this

    expect(logSpy).toHaveBeenCalledTimes(1);
  });
});

describe('newestAlertRow — cursor advancement', () => {
  it('picks the row with the latest lastSeenAt regardless of array order', () => {
    const rows = [makeAlert({ id: 'a', lastSeenAt: '2026-08-19T12:00:00.000Z' }), makeAlert({ id: 'b', lastSeenAt: '2026-08-19T12:05:00.000Z' })];
    expect(newestAlertRow(rows)!.id).toBe('b');
  });

  it('breaks a tie at the same lastSeenAt by the lexicographically greater id — matches gateway-activity\'s newestRow tie-break exactly, so a same-timestamp pair can never regress the cursor', () => {
    const rows = [makeAlert({ id: 'aaa', lastSeenAt: '2026-08-19T12:00:00.000Z' }), makeAlert({ id: 'zzz', lastSeenAt: '2026-08-19T12:00:00.000Z' })];
    expect(newestAlertRow(rows)!.id).toBe('zzz');
  });

  it('returns undefined for an empty batch — the caller must not advance the cursor on a quiet poll', () => {
    expect(newestAlertRow([])).toBeUndefined();
  });
});
