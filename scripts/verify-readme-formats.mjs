#!/usr/bin/env node
// Derives the set of documented formats from the README table and
// cross-checks it against the CLI's own FORMATS array (its single source of
// truth, echoed in --help/error text). Fails loudly on drift in either
// direction — a format the CLI supports but the README omits, or a stale
// README row for a format the CLI no longer has — rather than relying on
// someone remembering to update both by hand.
// Run: node scripts/verify-readme-formats.mjs
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const cliSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'index.ts'), 'utf8');
const readme = fs.readFileSync(path.join(__dirname, '..', 'README.md'), 'utf8');

let failures = 0;
function check(name, cond, detail) {
  if (cond) console.log(`  ok  ${name}`);
  else { failures++; console.log(`FAIL  ${name}${detail ? `: ${detail}` : ''}`); }
}

// Pull the FORMATS array literal straight out of index.ts source — this is
// what --format validation and --help actually use at runtime.
const formatsMatch = cliSrc.match(/const FORMATS: Format\[\] = \[([\s\S]*?)\];/);
if (!formatsMatch) {
  console.error('Could not find the FORMATS array in src/index.ts — has it been renamed?');
  process.exit(2);
}
const cliFormats = [...formatsMatch[1].matchAll(/'([a-z-]+)'/g)].map((m) => m[1]);
console.log('CLI FORMATS:', cliFormats.join(', '));

// Pull every `format` value documented in the README's Formats table.
const readmeSection = readme.split('## Formats')[1]?.split('## ')[0] ?? '';
const readmeFormats = [...readmeSection.matchAll(/^\|\s*`([a-z-]+)`/gm)].map((m) => m[1]);
console.log('README formats:', readmeFormats.join(', '));

const missingFromReadme = cliFormats.filter((f) => !readmeFormats.includes(f));
const staleInReadme = readmeFormats.filter((f) => !cliFormats.includes(f));

check('every CLI-supported format is documented in the README', missingFromReadme.length === 0, `missing: ${missingFromReadme.join(', ')}`);
check('README documents no format the CLI does not actually support', staleInReadme.length === 0, `stale: ${staleInReadme.join(', ')}`);
check('at least one format found in each source (sanity check the parsing itself worked)', cliFormats.length > 0 && readmeFormats.length > 0);

console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'} — ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
