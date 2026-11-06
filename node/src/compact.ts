import * as b64 from './base64url.js';
import { KeyNotFoundError, MalformedTokenError, UnsupportedAlgorithmError } from './errors.js';
import { isObject, type JSONObject } from './json.js';
import { Key } from './key.js';
import type { KeySet } from './keyset.js';

export type Claims = JSONObject;

export interface Header {
  alg: string;
  enc?: string;
  typ?: string;
  kid?: string;
  [name: string]: unknown;
}

export interface DecodedToken {
  header: Header;
  claims: Claims;
}

const RESERVED = new Set(['alg', 'enc', 'zip', 'crit']);

export function split(token: string, count: 3 | 5): string[] {
  const parts = typeof token === 'string' ? token.split('.') : [];
  if (parts.length !== count) throw new MalformedTokenError(`token must have ${count} parts`);
  return parts;
}

export function parseHeader(segment: string): Header {
  const header = parseObject(b64.decode(segment), 'header');
  if (typeof header.alg !== 'string') throw new MalformedTokenError('header has no alg');
  if (header.kid !== undefined && typeof header.kid !== 'string') {
    throw new MalformedTokenError('header kid must be a string');
  }
  return header as Header;
}

export function parseClaims(payload: Buffer): Claims {
  return parseObject(payload, 'payload');
}

/** Rejects `none`, unknown or disallowed algorithms, and the unsupported `crit` and `zip` headers. */
export function checkHeader(
  header: Header,
  isKnown: (alg: string) => boolean,
  allowed: readonly string[] | undefined,
): void {
  if (header.alg.toLowerCase() === 'none') throw new UnsupportedAlgorithmError('"none" is not supported');
  if (!isKnown(header.alg)) throw new UnsupportedAlgorithmError(`unsupported alg ${header.alg}`);
  if (allowed && !allowed.includes(header.alg)) throw new UnsupportedAlgorithmError(`${header.alg} is not allowed`);
  if ('crit' in header) throw new UnsupportedAlgorithmError('crit header is not supported');
  if ('zip' in header) throw new UnsupportedAlgorithmError('zip header is not supported');
}

export function buildHeader(
  base: { alg: string; enc?: string; typ?: string; kid?: string },
  extras: JSONObject = {},
): Header {
  const header: Header = { alg: base.alg };
  if (base.enc !== undefined) header.enc = base.enc;
  header.typ = base.typ ?? 'JWT';
  if (base.kid !== undefined) header.kid = base.kid;
  for (const [name, value] of Object.entries(extras)) {
    if (!RESERVED.has(name)) header[name] = value;
  }
  return header;
}

/**
 * Picks the keys to try for a token. A header `kid` selects exactly one key from a set;
 * without one, every key that passes `check` is a candidate.
 */
export function selectKeys(source: Key | KeySet, header: Header, check: (key: Key) => void): Key[] {
  if (source instanceof Key) {
    check(source);
    return [source];
  }
  if (header.kid !== undefined) {
    const key = source.get(header.kid);
    if (!key) throw new KeyNotFoundError(`no key with the token's kid`);
    check(key);
    return [key];
  }
  const keys = source.keys.filter((key) => {
    try {
      check(key);
      return true;
    } catch {
      return false;
    }
  });
  if (keys.length === 0) throw new KeyNotFoundError(`no key fits ${header.alg}`);
  return keys;
}

/** Decodes a JWS without verifying anything. */
export function decode(token: string): DecodedToken {
  const [header, payload] = split(token, 3);
  return { header: parseHeader(header!), claims: parseClaims(b64.decode(payload!)) };
}

function parseObject(bytes: Buffer, what: string): JSONObject {
  let value: unknown;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new MalformedTokenError(`${what} is not valid JSON`);
  }
  if (!isObject(value)) throw new MalformedTokenError(`${what} must be a JSON object`);
  return value;
}
