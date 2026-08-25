// Shadow AI Discovery P1 task 10 (SAD-11) — `maindala tail`'s alert event type. Unit tests
// against the pure mapping/rendering/cursor helpers rather than the org-scoped `tailActivity`
// polling loop itself (an unbounded `while (true)`, not a natural fit for a fast unit test) —
// these are the exact functions that carry the new alert-specific logic.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { toAlertTailEvent, renderLine, newestAlertRow, createBatchPrinter, signupForTelemetryToken, isInteractive, type AlertRow } from './tail.js';

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

// ─── Telemetry Signup Consented Lead Capture ─────────────────────────────────────
// See aidlc-docs/design-artifacts/telemetry-signup-consent-2026-08.md in the
// maindala/maindala monorepo. Server-side behavior (dedup, opt_in_at, lead creation)
// is already covered by real Postgres integration tests there — these tests cover
// only what the CLI is responsible for: sending the right request shape, and never
// prompting (or defaulting to consent) outside a real interactive terminal.

function capturedBody(mockFetch: ReturnType<typeof vi.fn>): Record<string, unknown> {
  const call = mockFetch.mock.calls[0];
  const init = call?.[1] as RequestInit;
  return JSON.parse(init.body as string) as Record<string, unknown>;
}

describe('signupForTelemetryToken — request shape', () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it('omits company/contactOptIn entirely when no consent argument is given — the exact pre-existing request shape, so an older server or a network trace sees no difference', async () => {
    const mockFetch = vi.fn(async () => ({ ok: true, json: async () => ({ token: 'mt_x' }) } as Response));
    vi.stubGlobal('fetch', mockFetch);

    await signupForTelemetryToken('me@example.com');

    const body = capturedBody(mockFetch);
    expect(body['email']).toBe('me@example.com');
    // JSON.stringify drops keys whose value is undefined — this is what makes the
    // "backward compatible" claim literally true on the wire, not just in the types.
    expect('company' in body).toBe(false);
    expect('contactOptIn' in body).toBe(false);
  });

  it('sends company alone without contactOptIn when only a company was given', async () => {
    const mockFetch = vi.fn(async () => ({ ok: true, json: async () => ({ token: 'mt_x' }) } as Response));
    vi.stubGlobal('fetch', mockFetch);

    await signupForTelemetryToken('me@example.com', { company: 'Acme' });

    const body = capturedBody(mockFetch);
    expect(body['company']).toBe('Acme');
    // The CLI-side equivalent of the server's TSC-TC3: supplying a company must never
    // imply consent by itself.
    expect('contactOptIn' in body).toBe(false);
  });

  it('sends both company and contactOptIn:true on explicit opt-in', async () => {
    const mockFetch = vi.fn(async () => ({ ok: true, json: async () => ({ token: 'mt_x' }) } as Response));
    vi.stubGlobal('fetch', mockFetch);

    await signupForTelemetryToken('me@example.com', { company: 'Acme', contactOptIn: true });

    const body = capturedBody(mockFetch);
    expect(body['company']).toBe('Acme');
    expect(body['contactOptIn']).toBe(true);
  });
});

describe('isInteractive — the TTY gate', () => {
  const originalStdinTTY = process.stdin.isTTY;
  const originalStdoutTTY = process.stdout.isTTY;

  afterEach(() => {
    Object.defineProperty(process.stdin, 'isTTY', { value: originalStdinTTY, configurable: true });
    Object.defineProperty(process.stdout, 'isTTY', { value: originalStdoutTTY, configurable: true });
  });

  it('is false when stdin is not a TTY, regardless of stdout', () => {
    Object.defineProperty(process.stdin, 'isTTY', { value: undefined, configurable: true });
    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });
    expect(isInteractive()).toBe(false);
  });

  it('is false when stdout is not a TTY, regardless of stdin — a redirected stdout means the prompt text itself would be invisible', () => {
    Object.defineProperty(process.stdin, 'isTTY', { value: true, configurable: true });
    Object.defineProperty(process.stdout, 'isTTY', { value: undefined, configurable: true });
    expect(isInteractive()).toBe(false);
  });

  it('is true only when both stdin and stdout are real TTYs', () => {
    Object.defineProperty(process.stdin, 'isTTY', { value: true, configurable: true });
    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });
    expect(isInteractive()).toBe(true);
  });
});
