#!/usr/bin/env node
// Proves checkTool() fails open on a genuine outage (unreachable
// host, malformed response body), not just on an HTTP error status — and
// that missing apiKey still throws (deliberate, preserved).
// Run: node scripts/verify-agent-guard-fail-open.mjs <path-to-agent-guard-dist-index.js>
import http from 'http';

const distPath = process.argv[2];
if (!distPath) {
  console.error('Usage: node verify-agent-guard-fail-open.mjs <agent-guard-dist-index.js>');
  process.exit(2);
}
const { AgentGuard } = await import(distPath);

let failures = 0;
async function check(name, fn) {
  try { await fn(); console.log(`  ok  ${name}`); }
  catch (err) { failures++; console.log(`FAIL  ${name}: ${err.message}`); }
}

// ── 1. Unreachable host (real outage — nothing listening on this port) ─────
await check('unreachable host: allow, does not throw', async () => {
  const guard = new AgentGuard({ apiKey: 'mx_test', gatewayUrl: 'http://127.0.0.1:1' });
  const result = await guard.checkTool('some-tool');
  if (result.allow !== true || result.reason !== 'guard_error') {
    throw new Error(`expected guard_error allow result, got ${JSON.stringify(result)}`);
  }
});

// ── 2. Malformed JSON response body with a 200 status ───────────────────────
await check('malformed 200 response body: allow, does not throw', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{not valid json{{{');
  });
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  try {
    const guard = new AgentGuard({ apiKey: 'mx_test', gatewayUrl: `http://localhost:${port}` });
    const result = await guard.checkTool('some-tool');
    if (result.allow !== true || result.reason !== 'guard_error') {
      throw new Error(`expected guard_error allow result, got ${JSON.stringify(result)}`);
    }
  } finally {
    server.close();
  }
});

// ── 3. A real 500 (the pre-existing !res.ok path — must be unaffected) ─────
await check('HTTP 500 response: allow, does not throw (regression check)', async () => {
  const server = http.createServer((req, res) => { res.writeHead(500); res.end(); });
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  try {
    const guard = new AgentGuard({ apiKey: 'mx_test', gatewayUrl: `http://localhost:${port}` });
    const result = await guard.checkTool('some-tool');
    if (result.allow !== true || result.reason !== 'guard_error') {
      throw new Error(`expected guard_error allow result, got ${JSON.stringify(result)}`);
    }
  } finally {
    server.close();
  }
});

// ── 4. A well-formed 200 response — real decision still returned correctly ──
await check('healthy 200 response: real decision returned unchanged', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ allow: false, reason: 'denied_by_policy', dlpPatterns: [] }));
  });
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  try {
    const guard = new AgentGuard({ apiKey: 'mx_test', gatewayUrl: `http://localhost:${port}` });
    const result = await guard.checkTool('some-tool');
    if (result.allow !== false || result.reason !== 'denied_by_policy') {
      throw new Error(`expected the real denial to pass through, got ${JSON.stringify(result)}`);
    }
  } finally {
    server.close();
  }
});

// ── 5. Missing apiKey: still throws — this is deliberate and must NOT change ──
await check('missing apiKey: throws (misconfiguration, not an outage)', async () => {
  const guard = new AgentGuard({});
  let threw = false;
  try { await guard.checkTool('some-tool'); } catch { threw = true; }
  if (!threw) throw new Error('did not throw');
});

console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'} — ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
