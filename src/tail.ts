// `maindala tail` — polls the catalog API's existing gateway-activity +
// a2a-activity endpoints (org-admin, mk_/session auth) with the
// opaque `since` cursor those routes now accept, and renders a live, colorized,
// merged stream of an org's governed tool calls + A2A delegations. Metadata only —
// these endpoints never carry prompts/args/results, only tool/target/decision/latency.
//
// Shadow AI Discovery P1 task 10 (SAD-11): also polls governance-alerts with the same
// cursor pattern, adding an 'alert' event kind to the org-scoped stream. Deliberately
// org-scoped only — governance_alerts is inherently org-scoped (produced by that org's
// detection sweep) and the route requires the same admin-gated mk_/session auth as
// gateway-activity/a2a-activity, so it has no equivalent on the free, zero-setup mt_ tier
// (which isn't tied to any org). Metadata only here too: rule id, severity, title, subject
// name, status, occurrence count — no raw evidence.

// Overridable via MAINDALA_CATALOG_URL so a future URL rotation doesn't
// require every installed copy of this CLI to be upgraded before it works.
const BASE_URL = process.env['MAINDALA_CATALOG_URL'] ?? 'https://api.maindala.com';
const POLL_INTERVAL_MS = 2000;
const NIL_UUID = '00000000-0000-0000-0000-000000000000';

// ─── Cursor encoding ──────────────────────────────────────────────────────────
// Deliberately duplicated from the platform's own cursor-encoding logic
// (~15 lines, no dependencies) rather than shared, since this CLI is published
// standalone. The CLI treats a row's own createdAt/id as the source of truth
// and never needs to decode a cursor itself.
function encodeCursor(t: string, id: string): string {
  return Buffer.from(JSON.stringify({ t, id })).toString('base64url');
}

// A pure time-based lookback (--since 10m) reuses the exact same cursor shape: the
// (createdAt, id) > (t, id) comparison on the server needs only a lower time bound,
// so a nil UUID id makes any row at/after that timestamp pass.
function encodeTimeLookbackCursor(sinceMs: number): string {
  return encodeCursor(new Date(Date.now() - sinceMs).toISOString(), NIL_UUID);
}

// Upper bound on --since — 30 days. Not a real security boundary (this only
// controls how far back a client-side poll starts), but an unbounded value
// is a footgun (e.g. a typo'd "300h" silently becomes a multi-week backfill)
// and "positive, bounded duration" is the documented contract this parses to.
const MAX_LOOKBACK_MS = 30 * 24 * 60 * 60 * 1000;

function parseDuration(input: string): number {
  const m = /^(\d+)(s|m|h)$/.exec(input.trim());
  if (!m) throw new Error(`Invalid --since duration "${input}" — use e.g. 30s, 10m, 2h`);
  const n = Number(m[1]);
  if (n === 0) throw new Error(`Invalid --since duration "${input}" — must be greater than zero.`);
  const unitMs = { s: 1000, m: 60_000, h: 3_600_000 }[m[2] as 's' | 'm' | 'h'];
  const ms = n * unitMs;
  if (ms > MAX_LOOKBACK_MS) {
    throw new Error(`Invalid --since duration "${input}" — the maximum lookback is 30 days (e.g. 720h).`);
  }
  return ms;
}

// ─── Raw row shapes (subset of the API response we actually render) ──────────
interface GatewayLogRow {
  id: string;
  serviceSlug: string;
  toolName: string;
  decision: string;
  latencyMs: number | null;
  createdAt: string;
}
interface A2aLogRow {
  id: string;
  callerAgentSlug: string;
  calleeAgentSlug: string;
  decision: string;
  reason: string;
  latencyMs: number | null;
  createdAt: string;
}
export interface AlertRow {
  id: string;
  ruleId: string;
  severity: string;
  title: string;
  status: string;
  subjectName: string | null;
  subjectId: string;
  occurrenceCount: number;
  lastSeenAt: string;
}

// ─── Normalized tail event ────────────────────────────────────────────────────
// alert events reuse `tool`/`target` for ruleId/subjectName (rather than a discriminated
// union) to keep the single dedup/filter/render pipeline below — `decision` is unused for
// alerts (status/severity/occurrenceCount carry the alert-specific fields instead).
export interface TailEvent {
  kind: 'tool_call' | 'a2a_call' | 'alert';
  ts: string;
  tool: string;
  target: string;
  decision: string;
  latencyMs: number | null;
  cursorId: string;
  cursorT: string;
  severity?: string;
  status?: string;
  occurrenceCount?: number;
  title?: string;
}

function toTailEvent(kind: 'tool_call' | 'a2a_call', row: GatewayLogRow | A2aLogRow): TailEvent {
  if (kind === 'tool_call') {
    const r = row as GatewayLogRow;
    return {
      kind, ts: r.createdAt, tool: r.toolName, target: r.serviceSlug,
      decision: r.decision, latencyMs: r.latencyMs, cursorId: r.id, cursorT: r.createdAt,
    };
  }
  const r = row as A2aLogRow;
  return {
    kind, ts: r.createdAt, tool: 'call_agent', target: r.calleeAgentSlug,
    decision: r.decision, latencyMs: r.latencyMs, cursorId: r.id, cursorT: r.createdAt,
  };
}

export function toAlertTailEvent(row: AlertRow): TailEvent {
  return {
    kind: 'alert', ts: row.lastSeenAt, tool: row.ruleId, target: row.subjectName ?? row.subjectId.slice(0, 8),
    decision: '', latencyMs: null, cursorId: row.id, cursorT: row.lastSeenAt,
    severity: row.severity, status: row.status, occurrenceCount: row.occurrenceCount, title: row.title,
  };
}

// ─── ANSI color (no dependency — this is the only place the CLI colorizes) ───
const COLOR: Record<string, string> = {
  allow: '\x1b[32m',   // green
  deny: '\x1b[31m',    // red
  redact: '\x1b[33m',  // amber
  flag: '\x1b[33m',    // amber
  telemetry: '\x1b[2m', // dim
  observed: '\x1b[2m',  // dim
};
// Alert coloring keys off severity, not decision (alerts don't have one).
const SEVERITY_COLOR: Record<string, string> = {
  critical: '\x1b[31m', // red
  high:     '\x1b[31m', // red
  medium:   '\x1b[33m', // amber
  low:      '\x1b[2m',  // dim
};
const RESET = '\x1b[0m';

export function renderLine(e: TailEvent): string {
  const time = new Date(e.ts).toLocaleTimeString();
  if (e.kind === 'alert') {
    const color = SEVERITY_COLOR[e.severity ?? ''] ?? '';
    const repeat = (e.occurrenceCount ?? 1) > 1 ? ` (×${e.occurrenceCount})` : '';
    return `${color}${time}  [alert]  ${e.tool} → ${e.target}  ${e.severity}  ${e.title}${repeat}  status=${e.status}${RESET}`;
  }
  const color = COLOR[e.decision] ?? '';
  const latency = e.latencyMs != null ? `${e.latencyMs}ms` : '—';
  const kindLabel = e.kind === 'a2a_call' ? 'a2a' : 'tool';
  return `${color}${time}  [${kindLabel}]  ${e.tool} → ${e.target}  ${e.decision}  ${latency}${RESET}`;
}

// ─── Fetching ──────────────────────────────────────────────────────────────────
async function fetchActivity(
  orgSlug: string, apiKey: string, path: 'gateway-activity' | 'a2a-activity', since: string | null,
): Promise<(GatewayLogRow | A2aLogRow)[]> {
  const qs = new URLSearchParams({ limit: '50' });
  if (since) qs.set('since', since);
  const res = await fetch(`${BASE_URL}/orgs/${encodeURIComponent(orgSlug)}/${path}?${qs.toString()}`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
  if (res.status === 403 || res.status === 404) {
    throw new Error(`Org "${orgSlug}" not found, or your key isn't an admin there.`);
  }
  if (!res.ok) throw new Error(`Failed to fetch ${path}: HTTP ${res.status}`);
  return res.json() as Promise<(GatewayLogRow | A2aLogRow)[]>;
}

// Same cursor contract as fetchActivity, against governance-alerts (task 10, SAD-11) —
// cursored on last_seen_at server-side, so a dedup-bumped "still happening" alert is a
// real event here, not just a first-occurrence one.
async function fetchAlerts(orgSlug: string, apiKey: string, since: string | null): Promise<AlertRow[]> {
  const qs = new URLSearchParams({ limit: '50' });
  if (since) qs.set('since', since);
  const res = await fetch(`${BASE_URL}/orgs/${encodeURIComponent(orgSlug)}/governance-alerts?${qs.toString()}`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
  if (res.status === 403 || res.status === 404) {
    throw new Error(`Org "${orgSlug}" not found, or your key isn't an admin there.`);
  }
  if (!res.ok) throw new Error(`Failed to fetch governance-alerts: HTTP ${res.status}`);
  return res.json() as Promise<AlertRow[]>;
}

// Finds the row with the max (createdAt, id) tuple, regardless of the array's sort
// order — the initial cursor-less fetch returns DESC (newest first), while
// cursor-based polls return ASC (oldest-of-new-batch first). Comparing by id as a
// tie-breaker (not just createdAt) matters whenever two rows share the exact same
// timestamp: picking an arbitrary one of them as the next cursor would let any
// sibling row with a lexicographically higher id incorrectly re-pass the server's
// `(created_at, id) > (cursor.t, cursor.id)` filter on the next poll, reappearing
// as a duplicate. The max-id-at-the-max-timestamp row is always a safe cursor.
function newestRow<T extends { createdAt: string; id: string }>(rows: T[]): T | undefined {
  if (rows.length === 0) return undefined;
  return rows.reduce((max, r) => {
    if (r.createdAt > max.createdAt) return r;
    if (r.createdAt === max.createdAt && r.id > max.id) return r;
    return max;
  });
}

// Same tie-break logic as newestRow, keyed on last_seen_at instead of created_at —
// governance-alerts' cursor field (see fetchAlerts).
export function newestAlertRow(rows: AlertRow[]): AlertRow | undefined {
  if (rows.length === 0) return undefined;
  return rows.reduce((max, r) => {
    if (r.lastSeenAt > max.lastSeenAt) return r;
    if (r.lastSeenAt === max.lastSeenAt && r.id > max.id) return r;
    return max;
  });
}

export interface TailOptions {
  json?: boolean;
  filterDecision?: string;
  filterTool?: string;
  since?: string;
}

// The `since` filter is deliberately inclusive (>=) server-side to never miss a
// row when timestamp precision is ambiguous (see activity-cursor.ts) — so the
// same row can legitimately be re-fetched across polls. Suppress re-printing via
// a bounded set of already-shown ids (oldest evicted first) rather than trusting
// the cursor alone to be exact.
const MAX_SEEN_IDS = 1000;
class SeenIds {
  private readonly order: string[] = [];
  private readonly set = new Set<string>();
  hasSeen(id: string): boolean {
    return this.set.has(id);
  }
  markSeen(id: string): void {
    if (this.set.has(id)) return;
    this.set.add(id);
    this.order.push(id);
    if (this.order.length > MAX_SEEN_IDS) {
      const evicted = this.order.shift();
      if (evicted) this.set.delete(evicted);
    }
  }
}

// tool_call/a2a_call rows are immutable once logged — the same id can only legitimately
// reappear because of the cursor's inclusive `>=` boundary (see activity-cursor.ts), and
// showing it twice would be a real duplicate. An alert row is different: the SAME id
// legitimately reappears with genuinely NEW information (occurrence_count bumped, a later
// last_seen_at) whenever the sweep sees the condition again — that's the whole point of
// SAD-11's "still happening" tail event, not a duplicate. Real bug caught live: keying dedup
// on cursorId alone silently swallowed every repeat-occurrence alert after its first
// sighting, because SeenIds had already marked that id seen and never unmarks it. Folding
// occurrenceCount into the dedup key for alerts (bare cursorId for everything else) fixes
// it — a bump produces a new key, a genuine re-delivery of unchanged data still doesn't.
function dedupKey(e: TailEvent): string {
  return e.kind === 'alert' ? `${e.cursorId}:${e.occurrenceCount ?? 1}` : e.cursorId;
}

// Shared by both the org-scoped (P1) and free-tier (P2) tail loops: dedup by id,
// apply --filter-*, sort chronologically, render. Kept as one function so a
// change to the dedup/filter/render contract only needs to happen once.
export function createBatchPrinter(options: TailOptions): (events: TailEvent[]) => void {
  const seen = new SeenIds();
  // --filter-decision/--filter-tool are documented (and were built) for tool_call/a2a_call
  // events — decision means allow/deny/etc, tool means a tool/call_agent name. Neither
  // concept maps cleanly onto an alert (no decision; `tool` reuses the field for ruleId,
  // which isn't what a user typing --filter-tool "search" means). Alerts bypass both filters
  // entirely rather than silently disappearing under a filter whose semantics don't apply to
  // them — a structurally different kind of event, always shown.
  const matchesFilter = (e: TailEvent): boolean => {
    if (e.kind === 'alert') return true;
    if (options.filterDecision && e.decision !== options.filterDecision) return false;
    if (options.filterTool && e.tool !== options.filterTool) return false;
    return true;
  };

  return (events: TailEvent[]): void => {
    // Dedup against already-processed ids first (independent of the display
    // filter) — a row excluded by --filter-* must still be marked seen, or it
    // would be re-fetched and re-evaluated on every single poll forever.
    const unseen = events.filter((e) => !seen.hasSeen(dedupKey(e)));
    for (const e of unseen) seen.markSeen(dedupKey(e));

    const sorted = unseen.filter(matchesFilter).sort((a, b) => a.ts.localeCompare(b.ts));
    for (const e of sorted) {
      if (options.json) {
        console.log(JSON.stringify(e.kind === 'alert'
          ? { kind: e.kind, ts: e.ts, ruleId: e.tool, subject: e.target, severity: e.severity, title: e.title, status: e.status, occurrenceCount: e.occurrenceCount }
          : { kind: e.kind, ts: e.ts, tool: e.tool, target: e.target, decision: e.decision, latencyMs: e.latencyMs }));
      } else {
        console.log(renderLine(e));
      }
    }
  };
}

export async function tailActivity(orgSlug: string, apiKey: string, options: TailOptions): Promise<void> {
  let gatewayCursor: string | null = options.since ? encodeTimeLookbackCursor(parseDuration(options.since)) : null;
  let a2aCursor: string | null = gatewayCursor;
  let alertCursor: string | null = gatewayCursor;
  const printBatch = createBatchPrinter(options);

  // Initial fetch: bootstrap cursors from the newest row of each stream (or the
  // synthetic time-lookback cursor from --since) — either way, the FIRST poll
  // still fetches everything from that cursor forward so nothing is missed.
  console.error(`Tailing "${orgSlug}"… (Ctrl+C to stop)\n`);

  // eslint-disable-next-line no-constant-condition
  while (true) {
    const [gatewayRows, a2aRows, alertRows] = await Promise.all([
      fetchActivity(orgSlug, apiKey, 'gateway-activity', gatewayCursor),
      fetchActivity(orgSlug, apiKey, 'a2a-activity', a2aCursor),
      fetchAlerts(orgSlug, apiKey, alertCursor),
    ]);

    const events = [
      ...gatewayRows.map((r) => toTailEvent('tool_call', r)),
      ...a2aRows.map((r) => toTailEvent('a2a_call', r)),
      ...alertRows.map(toAlertTailEvent),
    ];
    printBatch(events);

    const newestGateway = newestRow(gatewayRows as GatewayLogRow[]);
    if (newestGateway) gatewayCursor = encodeCursor(newestGateway.createdAt, newestGateway.id);
    const newestA2a = newestRow(a2aRows as A2aLogRow[]);
    if (newestA2a) a2aCursor = encodeCursor(newestA2a.createdAt, newestA2a.id);
    const newestAlert = newestAlertRow(alertRows);
    if (newestAlert) alertCursor = encodeCursor(newestAlert.lastSeenAt, newestAlert.id);

    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
}

// ─── Zero-setup stream (no org, mt_ token) ───────────────────────────────────

const GATEWAY_URL = 'https://mcp.maindala.com';

interface FreeTelemetryEvent {
  id: string;
  ts: number; // epoch ms, server-assigned — no precision-loss concerns (see P1's
              // activity-cursor.ts note; this path never round-trips through a
              // lossy ISO-string cursor, since/filtering is a plain number).
  kind: 'tool_call' | 'a2a_call';
  toolName: string;
  target: string;
  latencyMs: number | null;
  decision: string | null;
  findingClasses: string[];
}

function toFreeTailEvent(e: FreeTelemetryEvent): TailEvent {
  return {
    kind: e.kind, ts: new Date(e.ts).toISOString(), tool: e.toolName, target: e.target,
    decision: e.decision ?? 'observed', latencyMs: e.latencyMs, cursorId: e.id, cursorT: String(e.ts),
  };
}

async function fetchFreeStream(token: string, sinceMs: number | null): Promise<FreeTelemetryEvent[]> {
  const qs = sinceMs != null ? `?since=${sinceMs}` : '';
  const res = await fetch(`${GATEWAY_URL}/telemetry/stream${qs}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.status === 401) throw new Error('Invalid or revoked telemetry token. Run `maindala tail --signup <email>` to get a new one.');
  if (!res.ok) throw new Error(`Failed to fetch telemetry stream: HTTP ${res.status}`);
  return res.json() as Promise<FreeTelemetryEvent[]>;
}

// Mints a fresh mt_ token with zero prior setup — the whole point of the free
// tier. Returns the plaintext token (shown once, matching every other key
// family's issuance convention) so the caller can save it via saveApiKey.
// Telemetry Signup Consented Lead Capture: company/contactOptIn are both optional on
// the server (backward compatible), so this signature is too — a caller that omits
// `consent` entirely gets the exact pre-existing behavior. See the maindala/maindala
// design doc aidlc-docs/design-artifacts/telemetry-signup-consent-2026-08.md §6-7.
export async function signupForTelemetryToken(
  email: string,
  consent?: { company?: string; contactOptIn?: boolean },
): Promise<string> {
  const res = await fetch(`${BASE_URL}/telemetry-signup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, company: consent?.company, contactOptIn: consent?.contactOptIn }),
  });
  if (res.status === 429) throw new Error('Too many signups from this network — try again in a minute.');
  if (!res.ok) throw new Error(`Signup failed: HTTP ${res.status}`);
  const data = await res.json() as { token: string };
  return data.token;
}

// Whether stdin AND stdout are both a real terminal — the only condition under which
// it's safe to prompt. A CI run or piped invocation must never manufacture consent by
// hanging on a prompt no one can answer (which would also silently opt someone in if a
// hung process defaulted to "yes" instead of exiting) — see design §4's "not negotiable"
// rules. Both streams matter: stdin could be a real TTY while stdout is redirected to a
// file, in which case the prompt text itself would vanish and the user would be
// answering blind.
export function isInteractive(): boolean {
  return Boolean(process.stdin.isTTY) && Boolean(process.stdout.isTTY);
}

// Interactive consent prompt shown only when isInteractive() and neither --company nor
// --contact-me was passed (index.ts decides that; this function just asks). Declining
// (a bare Enter) is the default — [y/N], never [Y/n] — matching design §4 exactly.
export async function promptForConsent(): Promise<{ company?: string; contactOptIn: boolean }> {
  const { createInterface } = await import('node:readline/promises');
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    console.log('\n  Free telemetry token — no account needed.\n');
    const company = (await rl.question('  Company (optional, press enter to skip): ')).trim();
    const answer = (await rl.question('  Can we email you about team governance? [y/N]: ')).trim().toLowerCase();
    return { company: company || undefined, contactOptIn: answer === 'y' || answer === 'yes' };
  } finally {
    rl.close();
  }
}

export async function tailFreeStream(token: string, options: TailOptions): Promise<void> {
  let sinceMs: number | null = options.since ? Date.now() - parseDuration(options.since) : null;
  const printBatch = createBatchPrinter(options);

  console.error('Tailing your free telemetry stream… (Ctrl+C to stop)\n');

  // eslint-disable-next-line no-constant-condition
  while (true) {
    const rows = await fetchFreeStream(token, sinceMs);
    printBatch(rows.map(toFreeTailEvent));

    const newest = rows.reduce<number | null>((max, r) => (max == null || r.ts > max ? r.ts : max), null);
    if (newest != null) sinceMs = newest;

    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
}
