// RFC 8785 (JSON Canonicalization Scheme) serializer used to compute evidence-log leaf hashes.
// Written in-tree instead of depending on a package because the published canonicalize
// releases need a newer Node than this CLI supports (>=18); a differential test pins this
// implementation to canonicalize@5.1.0 on every input the verifier can see (parsed JSON).

function str(s: string): string {
  // JCS forbids lone surrogates (they have no UTF-8 form); JSON.stringify would silently escape them.
  if (/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(s)) throw new Error('Lone surrogate is not allowed');
  return JSON.stringify(s);
}

function prim(v: unknown): string {
  if (typeof v === 'number') {
    if (Number.isNaN(v)) throw new Error('NaN is not allowed');
    if (!Number.isFinite(v)) throw new Error('Infinity is not allowed');
    return JSON.stringify(v); // ECMAScript number-to-string is exactly what RFC 8785 specifies
  }
  if (typeof v === 'string') return str(v);
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  return 'null';
}

const dropped = (v: unknown): boolean => v === undefined || typeof v === 'symbol' || typeof v === 'function';

function ser(v: unknown): string {
  if (v === null || typeof v !== 'object') return prim(v);
  if (Array.isArray(v)) return `[${v.map((e) => (dropped(e) ? 'null' : ser(e))).join(',')}]`;
  const o = v as Record<string, unknown>;
  // Default sort orders by UTF-16 code unit, the order RFC 8785 requires.
  const parts: string[] = [];
  for (const k of Object.keys(o).sort()) if (!dropped(o[k])) parts.push(`${str(k)}:${ser(o[k])}`);
  return `{${parts.join(',')}}`;
}

/** Canonical JSON text of a JSON-shaped value, or undefined when the value itself has no JSON form. */
export function canonicalize(value: unknown): string | undefined {
  return dropped(value) ? undefined : ser(value);
}
