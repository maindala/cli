import fs from 'fs';
import path from 'path';
import { resolveWithinRoot, assertValidSlug } from './safe-path.js';

// Frontmatter fields (name/description/version) come from the catalog —
// meta.name/description/version are server-returned, not something the
// local user typed. Always double-quote them in generated YAML frontmatter
// so a crafted value (e.g. a description containing a literal newline
// followed by another "key: value" line) can't inject additional
// frontmatter keys or break out of the block; it just becomes an oddly
// escaped string value, which is inert.
function yamlDoubleQuote(value: string): string {
  const escaped = value
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r\n/g, '\\n')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\n')
    .replace(/\t/g, '\\t');
  return `"${escaped}"`;
}

// For contexts that aren't YAML (a markdown heading) but still splice
// server-returned metadata into structural output: collapse newlines so a
// crafted name can't inject extra lines below what reads as a heading.
function singleLine(value: string): string {
  return value.replace(/[\r\n]+/g, ' ').trim();
}

export type Format =
  | 'claude'
  | 'claude-skill'
  | 'cursor'
  | 'copilot'
  | 'windsurf'
  | 'openclaw'
  | 'zed'
  | 'continue'
  | 'cline'
  | 'raw';

const MARKER_START = (slug: string) => `<!-- maindala:${slug}:start -->`;
const MARKER_END = (slug: string) => `<!-- maindala:${slug}:end -->`;

function upsertBlock(filePath: string, slug: string, content: string): void {
  const start = MARKER_START(slug);
  const end = MARKER_END(slug);
  const block = `${start}\n${content.trim()}\n${end}`;

  if (fs.existsSync(filePath)) {
    const existing = fs.readFileSync(filePath, 'utf8');
    const startIdx = existing.indexOf(start);
    const endIdx = existing.indexOf(end);
    if (startIdx !== -1 && endIdx !== -1) {
      const updated = existing.slice(0, startIdx) + block + existing.slice(endIdx + end.length);
      fs.writeFileSync(filePath, updated, 'utf8');
      return;
    }
    fs.appendFileSync(filePath, `\n\n${block}\n`);
  } else {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, `${block}\n`);
  }
}

export function writeClaude(cwd: string, slug: string, content: string): string {
  assertValidSlug(slug);
  const filePath = path.join(cwd, 'CLAUDE.md');
  upsertBlock(filePath, slug, content);
  return filePath;
}

export function writeCursor(cwd: string, slug: string, name: string, description: string, content: string): string {
  assertValidSlug(slug);
  const dir = path.join(cwd, '.cursor', 'rules');
  fs.mkdirSync(dir, { recursive: true });
  const filePath = resolveWithinRoot(dir, `${slug}.mdc`);
  const mdc = `---
description: ${yamlDoubleQuote(description)}
alwaysApply: false
---

${content.trim()}
`;
  fs.writeFileSync(filePath, mdc, 'utf8');
  return filePath;
}

export function writeCopilot(cwd: string, slug: string, name: string, content: string): string {
  assertValidSlug(slug);
  const dir = path.join(cwd, '.github');
  fs.mkdirSync(dir, { recursive: true });
  const filePath = path.join(dir, 'copilot-instructions.md');
  upsertBlock(filePath, slug, content);
  return filePath;
}

export function writeWindsurf(cwd: string, slug: string, content: string): string {
  assertValidSlug(slug);
  const filePath = path.join(cwd, '.windsurfrules');
  upsertBlock(filePath, slug, content);
  return filePath;
}

export function writeOpenclaw(cwd: string, slug: string, name: string, description: string, version: string, content: string): string {
  assertValidSlug(slug);
  const dir = path.join(cwd, '.openclaw', 'skills');
  fs.mkdirSync(dir, { recursive: true });
  const filePath = resolveWithinRoot(dir, `${slug}.md`);
  const skill = `---
name: ${yamlDoubleQuote(name)}
description: ${yamlDoubleQuote(description)}
version: ${yamlDoubleQuote(version)}
---

${content.trim()}
`;
  fs.writeFileSync(filePath, skill, 'utf8');
  return filePath;
}

export function writeRaw(cwd: string, slug: string, content: string): string {
  assertValidSlug(slug);
  const filePath = resolveWithinRoot(cwd, `${slug}.md`);
  fs.writeFileSync(filePath, content, 'utf8');
  return filePath;
}

// Claude Code native skill format: .claude/skills/<slug>/SKILL.md with name +
// description frontmatter (the description is what Claude uses to auto-invoke the skill).
export function writeClaudeSkill(cwd: string, slug: string, name: string, description: string, content: string): string {
  assertValidSlug(slug);
  const dir = resolveWithinRoot(path.join(cwd, '.claude', 'skills'), slug);
  fs.mkdirSync(dir, { recursive: true });
  const filePath = path.join(dir, 'SKILL.md');
  const skill = `---
name: ${yamlDoubleQuote(name)}
description: ${yamlDoubleQuote(description)}
---

${content.trim()}
`;
  fs.writeFileSync(filePath, skill, 'utf8');
  return filePath;
}

// Zed: single project-root .rules file (upsert block so multiple skills coexist).
export function writeZed(cwd: string, slug: string, content: string): string {
  assertValidSlug(slug);
  const filePath = path.join(cwd, '.rules');
  upsertBlock(filePath, slug, content);
  return filePath;
}

// Continue: one markdown rule per skill under .continue/rules/, with a name header.
export function writeContinue(cwd: string, slug: string, name: string, content: string): string {
  assertValidSlug(slug);
  const dir = path.join(cwd, '.continue', 'rules');
  fs.mkdirSync(dir, { recursive: true });
  const filePath = resolveWithinRoot(dir, `${slug}.md`);
  const rule = `---
name: ${yamlDoubleQuote(name)}
alwaysApply: false
---

${content.trim()}
`;
  fs.writeFileSync(filePath, rule, 'utf8');
  return filePath;
}

// Cline / Roo: one markdown file per skill under the .clinerules/ folder.
export function writeCline(cwd: string, slug: string, name: string, content: string): string {
  assertValidSlug(slug);
  const dir = path.join(cwd, '.clinerules');
  fs.mkdirSync(dir, { recursive: true });
  const filePath = resolveWithinRoot(dir, `${slug}.md`);
  fs.writeFileSync(filePath, `# ${singleLine(name)}\n\n${content.trim()}\n`, 'utf8');
  return filePath;
}

export function writeFormat(
  format: Format,
  cwd: string,
  slug: string,
  meta: { name: string; description: string; version: string },
  content: string
): string {
  // Validated here as well as in each writer below. Every exported writer
  // validates its own slug, so this module is safe on its own terms no matter
  // which entry point is used — this call is not what makes that true, it just
  // fails fast before dispatching. (An earlier version validated ONLY here and
  // claimed the same property; that was wrong, because all ten writers are
  // exported and callable directly. `resolveWithinRoot` is the containment
  // backstop underneath both.)
  assertValidSlug(slug);
  switch (format) {
    case 'claude':
      return writeClaude(cwd, slug, content);
    case 'claude-skill':
      return writeClaudeSkill(cwd, slug, meta.name, meta.description, content);
    case 'cursor':
      return writeCursor(cwd, slug, meta.name, meta.description, content);
    case 'copilot':
      return writeCopilot(cwd, slug, meta.name, content);
    case 'windsurf':
      return writeWindsurf(cwd, slug, content);
    case 'openclaw':
      return writeOpenclaw(cwd, slug, meta.name, meta.description, meta.version, content);
    case 'zed':
      return writeZed(cwd, slug, content);
    case 'continue':
      return writeContinue(cwd, slug, meta.name, content);
    case 'cline':
      return writeCline(cwd, slug, meta.name, content);
    case 'raw':
      return writeRaw(cwd, slug, content);
  }
}
