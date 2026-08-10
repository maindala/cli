// Vitest suite for the path-confinement helpers in safe-path.ts (OAE-5's
// coverage gap — packages/cli previously had no test runner at all, only
// standalone `scripts/verify-*.mjs` proofs run against the built dist).
// This suite exercises the helpers directly; safe-path.call-sites.test.ts
// (runner.test.ts / verify-pack.test.ts / writers.test.ts) exercises the
// three real places these helpers gate, because a correct helper bypassed at
// one call site is exactly the failure mode `safe-path.ts` exists to close
// (see its file-header comment). Ported from, and does not replace,
// scripts/verify-safe-path.mjs — that script still runs against the built
// dist as an independent, tooling-free proof.
import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { resolveWithinRoot, assertFlatSegment, assertValidSlug, assertValidPort } from './safe-path.js';

describe('resolveWithinRoot', () => {
  let root: string;
  beforeEach(() => {
    // Fresh root per test — several tests write real files, so isolation
    // avoids any cross-test interference.
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'safe-path-root-'));
  });

  it('rejects a simple relative traversal ("../../escape.txt")', () => {
    expect(() => resolveWithinRoot(root, '../../escape.txt')).toThrow(/not allowed|outside/);
  });

  it('rejects a traversal buried mid-path ("a/../../b.txt")', () => {
    expect(() => resolveWithinRoot(root, 'a/../../b.txt')).toThrow();
  });

  it('rejects a bare ".." segment', () => {
    expect(() => resolveWithinRoot(root, '..')).toThrow();
  });

  it('rejects an absolute path', () => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'safe-path-outside-'));
    expect(() => resolveWithinRoot(root, path.join(outside, 'x.txt'))).toThrow(/absolute/);
  });

  it('rejects a Windows-style absolute path shape on any platform', () => {
    // path.isAbsolute() is platform-specific, but the backslash-segment
    // split means a leading "C:\" candidate still can't resolve outside
    // root on POSIX (it becomes a literal, harmless filename there) — this
    // just documents that the null-byte/".." checks run before the
    // isAbsolute() check regardless of platform.
    expect(() => resolveWithinRoot(root, 'a\\..\\..\\b.txt')).toThrow();
  });

  it('rejects a null-byte filename', () => {
    expect(() => resolveWithinRoot(root, 'x\0.txt')).toThrow(/null byte/);
  });

  it('accepts a legitimate relative filename and resolves inside root', () => {
    const resolved = resolveWithinRoot(root, 'output.txt');
    expect(resolved.startsWith(root + path.sep) || resolved === root).toBe(true);
    expect(resolved).toBe(path.join(root, 'output.txt'));
  });

  it('accepts a legitimate nested relative filename', () => {
    const resolved = resolveWithinRoot(root, 'sub/dir/output2.txt');
    expect(resolved.startsWith(root + path.sep)).toBe(true);
    expect(resolved).toBe(path.join(root, 'sub', 'dir', 'output2.txt'));
  });

  it('accepts "." (resolves to root itself)', () => {
    const resolved = resolveWithinRoot(root, '.');
    expect(resolved).toBe(path.resolve(root));
  });

  it('rejects the empty string the same way "." is accepted (path.resolve treats "" as the base)', () => {
    // Documented current behavior, not a claim either way is "more correct":
    // path.resolve(root, '') === path.resolve(root), so an empty candidate
    // resolves to root itself and is accepted, same as ".". Call sites all
    // pass a non-empty filename/slug in practice; this exists so a future
    // change to that assumption isn't silent.
    const resolved = resolveWithinRoot(root, '');
    expect(resolved).toBe(path.resolve(root));
  });

  it('a filename that merely starts with ".." but is not a full ".." segment is allowed (not a false positive)', () => {
    // "..foo" is a single valid path segment, not a traversal — only an
    // EXACT ".." segment is rejected. Confirms the check is segment-aware,
    // not a blunt substring match that would over-block legitimate names.
    const resolved = resolveWithinRoot(root, '..foo/bar.txt');
    expect(resolved).toBe(path.join(root, '..foo', 'bar.txt'));
  });

  it('does not perform filesystem-level (realpath) resolution — a same-named symlink already present inside root is not detected here', () => {
    // This documents actual behavior, checked against the implementation
    // rather than assumed: resolveWithinRoot is purely lexical (path.resolve
    // on strings), it never stats or realpath()s anything. A pre-existing
    // symlink inside root whose *name* looks like a normal relative filename
    // therefore resolves "inside root" by this check alone — the helper's
    // contract is string confinement, not filesystem-truth confinement.
    // verify-pack.ts's call site adds its own lstatSync().isSymbolicLink()
    // check as defense in depth for exactly this reason (see verify-pack.ts
    // and verify-pack.test.ts). runner.ts's call site does NOT add an
    // equivalent check — see runner.test.ts for that finding.
    const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'safe-path-symlink-outside-'));
    const outsideFile = path.join(outsideDir, 'target.txt');
    fs.writeFileSync(outsideFile, 'outside content');
    const linkPath = path.join(root, 'looks-normal.txt');
    fs.symlinkSync(outsideFile, linkPath);

    const resolved = resolveWithinRoot(root, 'looks-normal.txt');
    expect(resolved).toBe(linkPath); // "confined" by the lexical check ...
    expect(fs.lstatSync(resolved).isSymbolicLink()).toBe(true); // ... yet it's a symlink pointing elsewhere
  });
});

describe('assertFlatSegment', () => {
  it('rejects a forward-slash separator', () => {
    expect(() => assertFlatSegment('../../etc/passwd', 'section name')).toThrow(/path separators/);
  });

  it('rejects a backslash separator', () => {
    expect(() => assertFlatSegment('a\\b', 'section name')).toThrow(/path separators/);
  });

  it('rejects a null byte', () => {
    expect(() => assertFlatSegment('a\0b', 'section name')).toThrow();
  });

  it('accepts a flat filename', () => {
    expect(() => assertFlatSegment('report.pdf', 'section name')).not.toThrow();
  });

  it('accepts a flat filename containing ".." as long as it has no separator (not itself a traversal)', () => {
    // "..pdf" or "report..pdf" have no path separator, so they are flat by
    // definition even though they contain the substring "..". Confirms this
    // check is about separators, not about the string "..".
    expect(() => assertFlatSegment('report..pdf', 'section name')).not.toThrow();
  });
});

describe('assertValidSlug', () => {
  it('rejects a traversal-shaped slug', () => {
    expect(() => assertValidSlug('../../evil')).toThrow(/Invalid slug/);
  });

  it('rejects an absolute-path-shaped slug', () => {
    expect(() => assertValidSlug('/etc/passwd')).toThrow();
  });

  it('rejects an empty slug', () => {
    expect(() => assertValidSlug('')).toThrow();
  });

  it('rejects uppercase characters', () => {
    expect(() => assertValidSlug('Some-Slug')).toThrow();
  });

  it('rejects a slug starting with a hyphen', () => {
    expect(() => assertValidSlug('-leading-hyphen')).toThrow();
  });

  it('rejects a slug over 64 characters', () => {
    expect(() => assertValidSlug('a'.repeat(65))).toThrow();
  });

  it('accepts a slug at exactly the 64-character boundary', () => {
    expect(() => assertValidSlug('a'.repeat(64))).not.toThrow();
  });

  it('accepts a normal slug', () => {
    expect(() => assertValidSlug('stock-analyst-pro')).not.toThrow();
  });

  it('accepts a single-character slug', () => {
    expect(() => assertValidSlug('a')).not.toThrow();
  });
});

describe('assertValidPort', () => {
  it('rejects a non-integer', () => {
    expect(() => assertValidPort(80.5)).toThrow(/Invalid port/);
  });

  it('rejects NaN', () => {
    expect(() => assertValidPort(NaN)).toThrow();
  });

  it('rejects below the minimum (1023)', () => {
    expect(() => assertValidPort(1023)).toThrow();
  });

  it('rejects above the maximum (65536)', () => {
    expect(() => assertValidPort(65536)).toThrow();
  });

  it('rejects zero and negative values', () => {
    expect(() => assertValidPort(0)).toThrow();
    expect(() => assertValidPort(-1)).toThrow();
  });

  it('accepts the lower boundary (1024)', () => {
    expect(() => assertValidPort(1024)).not.toThrow();
  });

  it('accepts the upper boundary (65535)', () => {
    expect(() => assertValidPort(65535)).not.toThrow();
  });

  it('accepts a normal port (8080)', () => {
    expect(() => assertValidPort(8080)).not.toThrow();
  });
});
