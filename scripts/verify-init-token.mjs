#!/usr/bin/env node
// Proves `maindala init` never echoes the full token, across every
// output stream. Run: node scripts/verify-init-token.mjs
import { initProject } from '../dist/init.js';
import fs from 'fs';
import os from 'os';
import path from 'path';

let failures = 0;
function check(name, cond, detail) {
  if (cond) console.log(`  ok  ${name}`);
  else { failures++; console.log(`FAIL  ${name}${detail ? `: ${detail}` : ''}`); }
}

// Real-shaped token, not a placeholder — 32 hex chars after the prefix,
// matching the actual mt_ format so the truncation math is representative.
const FULL_TOKEN = 'mt_' + 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'init-verify-'));
const prevCwd = process.cwd();
process.chdir(cwd);

const result = initProject(FULL_TOKEN);
const allOutput = result.lines.join('\n');
console.log('--- init output ---');
console.log(allOutput);
console.log('-------------------');

check('exit code is 0 (success)', result.exitCode === 0);
check('full token does NOT appear anywhere in the returned output', !allOutput.includes(FULL_TOKEN));
check('a truncated form of the token DOES appear (proves it wasn\'t just deleted)', allOutput.includes(FULL_TOKEN.slice(0, 11)));

const examplePath = path.join(cwd, 'maindala-telemetry.example.ts');
const exampleContent = fs.readFileSync(examplePath, 'utf8');
check('scaffolded example file does not contain the token', !exampleContent.includes(FULL_TOKEN));
check('scaffolded example file reads the token from process.env', exampleContent.includes('process.env.MAINDALA_TELEMETRY_TOKEN'));

// Rejection path: no token configured — must not leak anything either (nothing to leak here, but confirm clean exit).
const result2 = initProject(undefined);
check('no-token case exits non-zero', result2.exitCode !== 0);
check('no-token case output contains no token-shaped string', !/mt_[a-f0-9]{10,}/.test(result2.lines.join('\n')));

process.chdir(prevCwd);
fs.rmSync(cwd, { recursive: true, force: true });

console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'} — ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
