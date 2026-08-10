// Path-confinement helper shared by every place this CLI writes or reads a
// filename that did not originate from the local user's own command-line
// argument — runtime-returned file results (runner.ts), evidence-pack manifest
// section names (verify-pack.ts), and install-target slugs (writers.ts). All
// three are untrusted in the same way: the value can come from a remote agent,
// a downloaded pack, or a catalog entry, and must never be able to resolve
// outside the directory this CLI intends to touch.
import path from 'path';

// Resolves `candidate` against `root` and throws unless the result stays
// strictly within `root`. Rejects absolute paths, `..` segments, and null
// bytes outright before ever calling path.resolve, so a candidate can't rely
// on platform-specific resolution quirks to slip past the containment check.
export function resolveWithinRoot(root: string, candidate: string): string {
  if (candidate.includes('\0')) {
    throw new Error(`Refusing unsafe path "${candidate}": contains a null byte.`);
  }
  if (path.isAbsolute(candidate)) {
    throw new Error(`Refusing unsafe path "${candidate}": absolute paths are not allowed.`);
  }
  const normalized = candidate.split(/[\\/]/);
  if (normalized.some((seg) => seg === '..')) {
    throw new Error(`Refusing unsafe path "${candidate}": ".." segments are not allowed.`);
  }

  const resolvedRoot = path.resolve(root);
  const resolvedCandidate = path.resolve(resolvedRoot, candidate);
  if (resolvedCandidate !== resolvedRoot && !resolvedCandidate.startsWith(resolvedRoot + path.sep)) {
    throw new Error(`Refusing unsafe path "${candidate}": resolves outside ${resolvedRoot}.`);
  }
  return resolvedCandidate;
}

// Stricter check for names that must be a single flat path segment (no
// directories at all) — used for evidence-pack section names, where the
// format is defined as flat filenames and any separator is itself suspicious
// before confinement is even checked.
export function assertFlatSegment(candidate: string, context: string): void {
  if (candidate.includes('/') || candidate.includes('\\') || candidate.includes('\0')) {
    throw new Error(`Refusing unsafe ${context} "${candidate}": must be a flat filename with no path separators.`);
  }
}

// Slug allowlist shared by every CLI entry point that turns a slug into a
// filename or directory name (writers.ts). Deliberately strict — lowercase
// alphanumerics and hyphens only, starting with an alphanumeric.
const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;

export function assertValidSlug(slug: string): void {
  if (!SLUG_RE.test(slug)) {
    throw new Error(`Invalid slug "${slug}" — expected lowercase alphanumerics and hyphens only.`);
  }
}

// Host-port allowlist for `maindala run`. Shared by the CLI entry point and
// runner.ts so there is one definition of a valid port rather than two that
// can drift — the port is interpolated into a `-p <port>:8080` docker argument,
// so an unvalidated value becomes part of a spawned command line. Ports below
// 1024 are excluded because binding them needs elevated privileges, which this
// command should never require.
const MIN_PORT = 1024;
const MAX_PORT = 65535;

export function assertValidPort(port: number): void {
  if (!Number.isInteger(port) || port < MIN_PORT || port > MAX_PORT) {
    throw new Error(`Invalid port "${port}" — must be an integer between ${MIN_PORT} and ${MAX_PORT}.`);
  }
}
