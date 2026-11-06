import type { Algorithm } from './algorithms.js';
import type { Claims, Header } from './compact.js';
import { InvalidClaimError, TokenExpiredError, TokenNotYetValidError } from './errors.js';

export interface VerifyOptions {
  /** Allowed `alg` values. Defaults to the key's `alg`, or every algorithm that fits the key. */
  algorithms?: readonly Algorithm[];
  issuer?: string | readonly string[];
  audience?: string | readonly string[];
  subject?: string;
  /** Expected header `typ`, compared case-insensitively. */
  typ?: string;
  /** Clock skew allowance in seconds for `exp`, `nbf` and `iat`. */
  leeway?: number;
  /** Maximum token age in seconds, measured from `iat`. */
  maxAge?: number;
  required?: readonly string[];
  /** Current time in unix seconds. */
  now?: number;
}

export function validateClaims(claims: Claims, header: Header, options: VerifyOptions): void {
  const now = options.now ?? Date.now() / 1000;
  const leeway = options.leeway ?? 0;
  const exp = numericDate(claims, 'exp');
  const nbf = numericDate(claims, 'nbf');
  const iat = numericDate(claims, 'iat');

  if (exp !== undefined && now >= exp + leeway) throw new TokenExpiredError();
  if (nbf !== undefined && now < nbf - leeway) throw new TokenNotYetValidError();
  if (iat !== undefined && iat > now + leeway) throw new InvalidClaimError('iat', '"iat" is in the future');

  if (options.maxAge !== undefined) {
    if (iat === undefined) throw new InvalidClaimError('iat', 'maxAge needs an "iat" claim');
    if (now - iat > options.maxAge + leeway) throw new TokenExpiredError('token is older than maxAge');
  }

  for (const name of options.required ?? []) {
    if (claims[name] === undefined) throw new InvalidClaimError(name, `missing "${name}" claim`);
  }

  if (options.issuer !== undefined && !toList(options.issuer).includes(claims.iss as string)) {
    throw new InvalidClaimError('iss');
  }

  if (options.audience !== undefined) {
    const expected = toList(options.audience);
    const aud = typeof claims.aud === 'string' ? [claims.aud] : claims.aud;
    if (!Array.isArray(aud) || !aud.some((value) => expected.includes(value))) {
      throw new InvalidClaimError('aud');
    }
  }

  if (options.subject !== undefined && claims.sub !== options.subject) throw new InvalidClaimError('sub');

  if (
    options.typ !== undefined &&
    (typeof header.typ !== 'string' || header.typ.toLowerCase() !== options.typ.toLowerCase())
  ) {
    throw new InvalidClaimError('typ', 'unexpected token type');
  }
}

function numericDate(claims: Claims, name: string): number | undefined {
  const value = claims[name];
  if (value === undefined) return undefined;
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new InvalidClaimError(name, `"${name}" must be a number`);
  }
  return value;
}

function toList(value: string | readonly string[]): readonly string[] {
  return typeof value === 'string' ? [value] : value;
}
