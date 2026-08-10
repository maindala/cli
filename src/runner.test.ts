// Vitest suite for runner.ts's runOneShot() — specifically the file-result
// write loop this is all about: "runner.ts ... passed a filename straight
// from the agent runtime's JSON response into fs.writeFileSync as a raw
// path — not joined to a root, not validated, not even forced relative."
// This exercises the REAL exported runOneShot(), not a copy of its logic —
// a correct helper bypassed at the call site is exactly the failure mode
// safe-path.ts exists to close, so the helper being correct (see
// safe-path.test.ts) proves nothing about this file on its own.
//
// Docker and the network are mocked (child_process.spawnSync/spawn, global
// fetch) so the test can run anywhere with no Docker daemon required; the
// filesystem is real, and every assertion below checks real files on disk,
// per the task's verification bar — not exit codes or thrown errors alone.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Payload, RunOptions } from './runner.js';

vi.mock('child_process', () => ({
  spawn: vi.fn(),
  spawnSync: vi.fn((_cmd: string, args: string[] = []) => {
    const sub = args[0];
    if (sub === 'port') return { status: 0, stdout: '0.0.0.0:54321\n', stderr: '' };
    // 'info' (preflightDocker), 'image'/'inspect' (ensureImage), 'run'
    // (container start), 'rm' (cleanup) — all succeed.
    return { status: 0, error: undefined, stdout: '', stderr: '' };
  }),
}));

function mockFetchSequence(files: Array<{ filename: string; content?: string }>): void {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    const u = String(url);
    if (u.endsWith('/health')) return { ok: true } as Response;
    if (u.endsWith('/run')) {
      return {
        ok: true,
        json: async () => ({ output: 'agent output', files }),
      } as unknown as Response;
    }
    throw new Error(`unexpected fetch to ${u}`);
  }));
}

const BASE_OPTS: RunOptions = {
  provider: 'anthropic',
  llmKey: 'fake-key',
  port: 8080,
  image: 'fake-image:latest',
  detach: false,
};
const PAYLOAD: Payload = { kind: 'single', bundle: '{}' };

describe('runOneShot — file-result write loop (real call site, mocked docker/network)', () => {
  let originalCwd: string;
  let tmpCwd: string;

  beforeEach(() => {
    originalCwd = process.cwd();
    tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'runner-test-cwd-'));
    process.chdir(tmpCwd);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(tmpCwd, { recursive: true, force: true });
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it('a legitimate filename is written inside cwd with the correct content', async () => {
    const { runOneShot } = await import('./runner.js');
    mockFetchSequence([{ filename: 'output.txt', content: Buffer.from('hello world').toString('base64') }]);

    await runOneShot('test-agent', 'Test Agent', PAYLOAD, BASE_OPTS);

    const written = path.join(tmpCwd, 'output.txt');
    expect(fs.existsSync(written)).toBe(true);
    expect(fs.readFileSync(written, 'utf8')).toBe('hello world');
  });

  it('a legitimate nested filename creates the intermediate directories inside cwd', async () => {
    const { runOneShot } = await import('./runner.js');
    mockFetchSequence([{ filename: 'sub/dir/out.txt', content: Buffer.from('nested').toString('base64') }]);

    await runOneShot('test-agent', 'Test Agent', PAYLOAD, BASE_OPTS);

    const written = path.join(tmpCwd, 'sub', 'dir', 'out.txt');
    expect(fs.existsSync(written)).toBe(true);
    expect(fs.readFileSync(written, 'utf8')).toBe('nested');
  });

  it('a server-controlled ../../ traversal filename is skipped, and nothing is written outside cwd', async () => {
    const sentinelDir = fs.mkdtempSync(path.join(os.tmpdir(), 'runner-test-sentinel-'));
    const sentinelPath = path.join(sentinelDir, 'pwned.txt');
    const sentinelBefore = 'untouched-sentinel-content';
    fs.writeFileSync(sentinelPath, sentinelBefore);

    const traversal = path.relative(tmpCwd, sentinelPath); // e.g. ../../.../pwned.txt
    const { runOneShot } = await import('./runner.js');
    mockFetchSequence([{ filename: traversal, content: Buffer.from('MALICIOUS').toString('base64') }]);

    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    await runOneShot('test-agent', 'Test Agent', PAYLOAD, BASE_OPTS);

    // Filesystem-level proof, not just "no throw": the sentinel is untouched
    // and no new file appeared in its directory.
    expect(fs.readFileSync(sentinelPath, 'utf8')).toBe(sentinelBefore);
    expect(fs.readdirSync(sentinelDir)).toEqual(['pwned.txt']);
    expect(errSpy.mock.calls.some((c) => String(c[0]).includes('skipped unsafe file result'))).toBe(true);

    fs.rmSync(sentinelDir, { recursive: true, force: true });
  });

  it('a server-controlled absolute-path filename is skipped, and nothing is written at that location', async () => {
    const sentinelDir = fs.mkdtempSync(path.join(os.tmpdir(), 'runner-test-sentinel-abs-'));
    const absoluteTarget = path.join(sentinelDir, 'absolute-pwned.txt');

    const { runOneShot } = await import('./runner.js');
    mockFetchSequence([{ filename: absoluteTarget, content: Buffer.from('MALICIOUS').toString('base64') }]);

    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    await runOneShot('test-agent', 'Test Agent', PAYLOAD, BASE_OPTS);

    expect(fs.existsSync(absoluteTarget)).toBe(false);
    expect(fs.readdirSync(sentinelDir)).toEqual([]);
    expect(errSpy.mock.calls.some((c) => String(c[0]).includes('skipped unsafe file result'))).toBe(true);

    fs.rmSync(sentinelDir, { recursive: true, force: true });
  });

  it('one malicious file among several does not block the legitimate ones from being written', async () => {
    const sentinelDir = fs.mkdtempSync(path.join(os.tmpdir(), 'runner-test-sentinel-mixed-'));
    const sentinelPath = path.join(sentinelDir, 'pwned.txt');
    fs.writeFileSync(sentinelPath, 'before');
    const traversal = path.relative(tmpCwd, sentinelPath);

    const { runOneShot } = await import('./runner.js');
    mockFetchSequence([
      { filename: traversal, content: Buffer.from('MALICIOUS').toString('base64') },
      { filename: 'good.txt', content: Buffer.from('good content').toString('base64') },
    ]);
    vi.spyOn(console, 'error').mockImplementation(() => {});

    await runOneShot('test-agent', 'Test Agent', PAYLOAD, BASE_OPTS);

    expect(fs.readFileSync(sentinelPath, 'utf8')).toBe('before');
    expect(fs.readFileSync(path.join(tmpCwd, 'good.txt'), 'utf8')).toBe('good content');

    fs.rmSync(sentinelDir, { recursive: true, force: true });
  });
});
