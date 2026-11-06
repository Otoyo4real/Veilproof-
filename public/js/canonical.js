// VeilProof canonical JSON — shared by Node and the browser.
// Pure, no imports. Object keys are sorted recursively, arrays keep
// their order, no whitespace. The same payload always serialises to the
// same string, so the same payload always hashes the same way.
//
// Semantics mirror JSON.stringify, except that BigInt (and any other
// non-JSON value) throws instead of being silently dropped: a hash must
// never be computed over a value that cannot round-trip through JSON.
// `undefined` object values are omitted and `undefined` array elements
// become null, exactly as JSON.stringify does.

export function canonicalJson(value) {
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value
      .map((v) => (v === undefined ? 'null' : canonicalJson(v)))
      .join(',')}]`;
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort();
    return `{${keys
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
      .join(',')}}`;
  }
  throw new Error(`canonicalJson: cannot serialise ${typeof value}`);
}
