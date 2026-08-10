#!/usr/bin/env node
// Proves format writers reject traversal-shaped slugs and neutralize
// frontmatter injection from server-returned metadata.
// Run: node scripts/verify-writers.mjs
import { writeFormat } from '../dist/writers.js';
import fs from 'fs';
import os from 'os';
import path from 'path';

let failures = 0;
function check(name, fn) {
  try { fn(); console.log(`  ok  ${name}`); }
  catch (err) { failures++; console.log(`FAIL  ${name}: ${err.message}`); }
}

const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), 'writers-verify-'));
const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'writers-outside-'));

// ── Traversal-shaped slugs must be rejected, for every format ──────────────
const traversalSlugs = ['../../evil', '..%2f..%2fevil', '/etc/passwd', 'a/../../b'];
const formats = ['claude-skill', 'cursor', 'openclaw', 'raw', 'continue', 'cline'];
for (const slug of traversalSlugs) {
  for (const format of formats) {
    check(`rejects traversal slug "${slug}" for format "${format}"`, () => {
      let threw = false;
      try {
        writeFormat(format, projectDir, slug, { name: 'x', description: 'x', version: '1.0.0' }, 'content');
      } catch { threw = true; }
      if (!threw) throw new Error('did not throw');
    });
  }
}

check('nothing was written outside the project directory after all traversal attempts', () => {
  const entries = fs.readdirSync(outsideDir);
  if (entries.length !== 0) throw new Error(`outside dir is not empty: ${entries.join(', ')}`);
});

// ── Legitimate slug still works for every format ────────────────────────────
for (const format of formats) {
  check(`legitimate slug writes correctly for format "${format}"`, () => {
    const p = writeFormat(format, projectDir, 'legit-skill', { name: 'Legit Skill', description: 'A real description', version: '1.0.0' }, 'body');
    if (!fs.existsSync(p)) throw new Error('file was not created');
    if (!p.startsWith(projectDir)) throw new Error('written outside project dir');
  });
}

// ── Frontmatter injection: a malicious description tries to inject a new YAML key ──
const maliciousDescription = 'legit\nalwaysApply: true\nmalicious_key: injected';
const injectedPath = writeFormat('cursor', projectDir, 'injection-test', {
  name: 'x', description: maliciousDescription, version: '1.0.0',
}, 'body');
const injectedContent = fs.readFileSync(injectedPath, 'utf8');
console.log('\n--- generated .mdc frontmatter ---');
console.log(injectedContent.split('\n\n')[0]);

check('malicious description is NOT interpreted as new YAML lines (no bare "malicious_key:" line)', () => {
  const lines = injectedContent.split('\n');
  const bareKeyLine = lines.find((l) => /^malicious_key:/.test(l));
  if (bareKeyLine) throw new Error(`injected as a real YAML key: "${bareKeyLine}"`);
});
check('the newline is escaped inside the quoted description value', () => {
  if (!injectedContent.includes('\\n')) throw new Error('expected an escaped \\n in the output');
});
check('description value is double-quoted', () => {
  if (!/^description: "/.test(injectedContent.split('\n')[1])) throw new Error('description line is not double-quoted');
});

// ── Same for claude-skill (name AND description) ────────────────────────────
const injectedPath2 = writeFormat('claude-skill', projectDir, 'injection-test-2', {
  name: 'legit"\nmalicious: true', description: 'fine', version: '1.0.0',
}, 'body');
const injectedContent2 = fs.readFileSync(injectedPath2, 'utf8');
console.log('\n--- generated SKILL.md frontmatter ---');
console.log(injectedContent2.split('\n\n')[0]);
check('quote-breaking name does not inject a new YAML key in claude-skill format', () => {
  const bareKeyLine = injectedContent2.split('\n').find((l) => /^malicious:/.test(l));
  if (bareKeyLine) throw new Error(`injected as a real YAML key: "${bareKeyLine}"`);
});

// ── cline heading injection (markdown, not YAML) ────────────────────────────
const clinePath = writeFormat('cline', projectDir, 'cline-injection', {
  name: 'Legit\n\n## Injected Heading\nmalicious body', description: 'x', version: '1.0.0',
}, 'real body');
const clineContent = fs.readFileSync(clinePath, 'utf8');
check('cline heading collapses injected newlines to a single line (no separate injected heading)', () => {
  const lines = clineContent.split('\n');
  if (lines[0] !== '# Legit ## Injected Heading malicious body') {
    throw new Error(`unexpected first line: "${lines[0]}"`);
  }
  // The real property: "Injected Heading" must not become ITS OWN markdown
  // heading (a line starting with "#"). It's fine for the substring to
  // appear as inert text inside the single collapsed h1.
  const secondHeadingLine = lines.slice(1).find((l) => /^#{1,6}\s/.test(l));
  if (secondHeadingLine) throw new Error(`a separate heading was injected: "${secondHeadingLine}"`);
});

fs.rmSync(projectDir, { recursive: true, force: true });
fs.rmSync(outsideDir, { recursive: true, force: true });

console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'} — ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
