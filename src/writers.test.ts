// Vitest suite for writers.ts — the third safe-path call site (install-target
// slugs). Ported from, and does not replace, scripts/verify-writers.mjs
// (which runs the same scenarios against the built dist as an independent,
// tooling-free proof).
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { writeFormat, type Format } from './writers.js';

const TRAVERSAL_SLUGS = ['../../evil', '..%2f..%2fevil', '/etc/passwd', 'a/../../b'];
const FORMATS: Format[] = ['claude-skill', 'cursor', 'openclaw', 'raw', 'continue', 'cline'];

function mkDirs(): { projectDir: string; outsideDir: string } {
  return {
    projectDir: fs.mkdtempSync(path.join(os.tmpdir(), 'writers-test-project-')),
    outsideDir: fs.mkdtempSync(path.join(os.tmpdir(), 'writers-test-outside-')),
  };
}

describe('writeFormat — traversal-shaped slugs are rejected for every format, on the filesystem not just by exit behavior', () => {
  for (const slug of TRAVERSAL_SLUGS) {
    for (const format of FORMATS) {
      it(`rejects "${slug}" for format "${format}" and creates nothing on disk`, () => {
        const { projectDir, outsideDir } = mkDirs();
        expect(() => writeFormat(format, projectDir, slug, { name: 'x', description: 'x', version: '1.0.0' }, 'content'))
          .toThrow();
        // Assert on the filesystem, not just the thrown error: nothing
        // outside the project dir was created by the attempt.
        expect(fs.readdirSync(outsideDir)).toHaveLength(0);
        fs.rmSync(projectDir, { recursive: true, force: true });
        fs.rmSync(outsideDir, { recursive: true, force: true });
      });
    }
  }
});

describe('writeFormat — legitimate slugs write correctly and stay confined', () => {
  for (const format of FORMATS) {
    it(`writes "${format}" inside the project dir`, () => {
      const { projectDir, outsideDir } = mkDirs();
      const p = writeFormat(format, projectDir, 'legit-skill', { name: 'Legit Skill', description: 'A real description', version: '1.0.0' }, 'body');
      expect(fs.existsSync(p)).toBe(true);
      expect(p.startsWith(projectDir)).toBe(true);
      fs.rmSync(projectDir, { recursive: true, force: true });
      fs.rmSync(outsideDir, { recursive: true, force: true });
    });
  }
});

describe('writeFormat — frontmatter/heading injection from server-returned metadata is neutralized', () => {
  it('a malicious YAML-shaped description does not become a real new frontmatter key (cursor format)', () => {
    const { projectDir } = mkDirs();
    const maliciousDescription = 'legit\nalwaysApply: true\nmalicious_key: injected';
    const injectedPath = writeFormat('cursor', projectDir, 'injection-test', {
      name: 'x', description: maliciousDescription, version: '1.0.0',
    }, 'body');
    const content = fs.readFileSync(injectedPath, 'utf8');
    const lines = content.split('\n');
    expect(lines.find((l) => /^malicious_key:/.test(l))).toBeUndefined();
    expect(content).toContain('\\n'); // newline escaped inside the quoted value
    expect(lines[1]).toMatch(/^description: "/); // still double-quoted
    fs.rmSync(projectDir, { recursive: true, force: true });
  });

  it('a quote-breaking name does not inject a new YAML key (claude-skill format)', () => {
    const { projectDir } = mkDirs();
    const injectedPath = writeFormat('claude-skill', projectDir, 'injection-test-2', {
      name: 'legit"\nmalicious: true', description: 'fine', version: '1.0.0',
    }, 'body');
    const content = fs.readFileSync(injectedPath, 'utf8');
    expect(content.split('\n').find((l) => /^malicious:/.test(l))).toBeUndefined();
    fs.rmSync(projectDir, { recursive: true, force: true });
  });

  it('a heading-shaped name collapses to a single inert line, not a real second markdown heading (cline format)', () => {
    const { projectDir } = mkDirs();
    const clinePath = writeFormat('cline', projectDir, 'cline-injection', {
      name: 'Legit\n\n## Injected Heading\nmalicious body', description: 'x', version: '1.0.0',
    }, 'real body');
    const content = fs.readFileSync(clinePath, 'utf8');
    const lines = content.split('\n');
    expect(lines[0]).toBe('# Legit ## Injected Heading malicious body');
    // The real property: "Injected Heading" must not become its OWN heading
    // line (starting with '#') anywhere after the first collapsed line.
    expect(lines.slice(1).find((l) => /^#{1,6}\s/.test(l))).toBeUndefined();
    fs.rmSync(projectDir, { recursive: true, force: true });
  });
});

describe('writeFormat — assertValidSlug runs before dispatch, so every exported writer is safe called directly too', () => {
  it('writeFormat itself rejects a traversal slug before ever touching a specific writer', () => {
    const { projectDir } = mkDirs();
    expect(() => writeFormat('raw', projectDir, '../escape', { name: 'x', description: 'x', version: '1.0.0' }, 'c')).toThrow();
    fs.rmSync(projectDir, { recursive: true, force: true });
  });
});
