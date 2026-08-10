#!/usr/bin/env node
// Proves --port and --since are rejected before reaching Docker or
// the tail query. Run: node scripts/verify-input-validation.mjs
import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

let failures = 0;
function check(name, cond, detail) {
  if (cond) console.log(`  ok  ${name}`);
  else { failures++; console.log(`FAIL  ${name}${detail ? `: ${detail}` : ''}`); }
}

const CLI = new URL('../dist/index.js', import.meta.url).pathname;

// A PATH with no `docker` binary reachable at all — if the port check ever
// let a bad value through to preflightDocker(), the error we'd see would be
// "Docker is required..." instead of our own port-validation message. This
// is the real proof the fake Docker boundary was never touched, not just a
// mocked assertion.
const noDockerPath = fs.mkdtempSync(path.join(os.tmpdir(), 'no-docker-path-'));
for (const bin of ['node', 'sh', 'bash', 'env']) {
  const p = execFileSync('command', ['-v', bin], { shell: '/bin/bash' }).toString().trim();
  if (p) fs.symlinkSync(p, path.join(noDockerPath, bin));
}

function runCli(args, envOverrides = {}) {
  try {
    const out = execFileSync(process.execPath, [CLI, ...args], {
      env: { ...process.env, PATH: noDockerPath, ...envOverrides },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { code: 0, stdout: out, stderr: '' };
  } catch (err) {
    return { code: err.status, stdout: err.stdout?.toString() ?? '', stderr: err.stderr?.toString() ?? '' };
  }
}

for (const badPort of ['abc', '99999', '0', '-1', 'NaN', '80.5']) {
  const r = runCli(['run', 'some-agent', '--port', badPort, '--llm-key', 'fake']);
  console.log(`--port "${badPort}": exit=${r.code} stderr="${r.stderr.trim()}"`);
  check(`--port "${badPort}" rejected with a non-zero exit`, r.code !== 0);
  check(`--port "${badPort}" error names the port, not Docker`, r.stderr.includes('--port') && !r.stderr.includes('Docker is required'));
}

// Control: a valid port should NOT be rejected by the validation step (it
// will still fail later for lack of a real Docker, but that's a DIFFERENT,
// later error — proving the port check itself passed valid input through).
{
  const r = runCli(['run', 'some-agent', '--port', '8080', '--llm-key', 'fake']);
  console.log(`--port "8080" (valid): exit=${r.code} stderr="${r.stderr.trim()}"`);
  check('valid --port is NOT rejected by the port-validation message', !r.stderr.includes('Invalid --port'));
}

// ── --since duration: zero and out-of-bound values must be rejected ──
function runTailBriefly(args) {
  try {
    execFileSync(process.execPath, [CLI, 'tail', 'some-org', ...args], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 1500,
    });
    return { code: 0, stderr: '' };
  } catch (err) {
    if (err.signal === 'SIGTERM') return { code: 'timeout', stderr: '' };
    return { code: err.status, stderr: err.stderr?.toString() ?? '' };
  }
}

for (const badSince of ['0s', '0m', '0h', '-5m', '1000h']) {
  const r = runTailBriefly(['--since', badSince, '--json']);
  console.log(`--since "${badSince}": code=${r.code} stderr="${r.stderr.trim()}"`);
  check(`--since "${badSince}" rejected with the duration-validation message`, r.stderr.includes('Invalid --since'));
}
{
  // Valid duration (under the 30-day bound): proves the parser accepted it
  // by checking the failure that DOES occur is unrelated to duration parsing
  // (this environment has no saved token, so it fails on auth instead —
  // same "look at what error DIDN'T happen" proof used for the port checks).
  const r = runTailBriefly(['--since', '300h', '--json']);
  console.log(`--since "300h" (valid): code=${r.code} stderr="${r.stderr.trim()}"`);
  check('--since "300h" is NOT rejected by duration validation', !r.stderr.includes('Invalid --since'));
}

console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'} — ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
