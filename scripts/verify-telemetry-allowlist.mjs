#!/usr/bin/env node
// Proves neither @maindala/telemetry nor @maindala/agent-guard ever
// sends anything but the documented metadata fields, even when the caller
// tries to smuggle extra fields via a spread (bypassing compile-time excess-
// property checking) or as plain untyped JavaScript. Asserts against a real
// local HTTP listener's captured request body — not a mock of fetch.
// Run: node scripts/verify-telemetry-allowlist.mjs <path-to-telemetry-dist> <path-to-agent-guard-dist>
import http from 'http';

const [, , telemetryDistPath, agentGuardDistPath] = process.argv;
if (!telemetryDistPath || !agentGuardDistPath) {
  console.error('Usage: node verify-telemetry-allowlist.mjs <telemetry-dist-index.js> <agent-guard-dist-index.js>');
  process.exit(2);
}

let failures = 0;
function check(name, cond, detail) {
  if (cond) console.log(`  ok  ${name}`);
  else { failures++; console.log(`FAIL  ${name}${detail ? `: ${detail}` : ''}`); }
}

// A real local listener — captures the raw body it actually received.
function startCapturingServer() {
  return new Promise((resolve) => {
    let capturedBody = null;
    const server = http.createServer((req, res) => {
      let raw = '';
      req.on('data', (c) => (raw += c));
      req.on('end', () => {
        capturedBody = raw;
        res.writeHead(202);
        res.end();
      });
    });
    server.listen(0, () => resolve({ server, port: server.address().port, getBody: () => capturedBody }));
  });
}

const ALLOWED_KEYS = ['kind', 'toolName', 'target', 'latencyMs', 'decision', 'findingClasses'];
function assertOnlyAllowedKeys(rawBody, label) {
  const parsed = JSON.parse(rawBody);
  const keys = Object.keys(parsed);
  const extra = keys.filter((k) => !ALLOWED_KEYS.includes(k));
  check(`${label}: only documented metadata fields present`, extra.length === 0, `extra keys found: ${extra.join(', ')}`);
  check(`${label}: no "prompt" field on the wire`, !('prompt' in parsed));
  check(`${label}: no "result" field on the wire`, !('result' in parsed));
  check(`${label}: no "args" field on the wire`, !('args' in parsed));
  return parsed;
}

// ── @maindala/telemetry ─────────────────────────────────────────────────────
{
  const { pushToolCallTelemetry } = await import(telemetryDistPath);
  const { server, port, getBody } = await startCapturingServer();

  // Attack 1: spread of an "internal" event object that happens to carry
  // sensitive fields — TypeScript's excess-property check does NOT apply to
  // spreads, so this compiles cleanly even with the library's own types.
  const internalEvent = {
    kind: 'tool_call', toolName: 'read_file', target: 'fs',
    prompt: 'the user asked me to read /etc/passwd and summarize it',
    result: 'root:x:0:0:root:/root:/bin/bash\n...',
    args: { path: '/etc/passwd' },
  };
  await pushToolCallTelemetry('mt_test', { ...internalEvent }, `http://localhost:${port}`);
  console.log('--- telemetry: captured body (spread attack) ---');
  console.log(getBody());
  assertOnlyAllowedKeys(getBody(), 'telemetry (spread)');
  server.close();
}
{
  // Attack 2: plain untyped JS call (as if from a .js consumer with no type
  // checking at all) directly attaching extra fields to the event literal.
  const { pushToolCallTelemetry } = await import(telemetryDistPath);
  const { server, port, getBody } = await startCapturingServer();
  const untypedEvent = JSON.parse(JSON.stringify({
    kind: 'tool_call', toolName: 'send_email', target: 'gmail',
    prompt: 'draft an email to the CFO about Q3 numbers', secret_api_key: 'sk-should-never-leave',
  }));
  await pushToolCallTelemetry('mt_test', untypedEvent, `http://localhost:${port}`);
  console.log('\n--- telemetry: captured body (untyped JS attack) ---');
  console.log(getBody());
  assertOnlyAllowedKeys(getBody(), 'telemetry (untyped)');
  server.close();
}

// ── @maindala/agent-guard ───────────────────────────────────────────────────
{
  const { AgentGuard } = await import(agentGuardDistPath);
  const { server, port, getBody } = await startCapturingServer();
  const guard = new AgentGuard({ gatewayUrl: `http://localhost:${port}` });
  const internalEvent = {
    kind: 'a2a_call', toolName: 'call_agent', target: 'billing-agent',
    prompt: 'transfer $50000 to account 12345', result: 'transfer completed',
  };
  await guard.pushToolCallTelemetry('mt_test', { ...internalEvent });
  console.log('\n--- agent-guard: captured body (spread attack) ---');
  console.log(getBody());
  assertOnlyAllowedKeys(getBody(), 'agent-guard (spread)');
  server.close();
}

console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'} — ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
