import { InvalidKeyError } from './errors.js';
import { isSupportedJWK, parseJWK, type JWK } from './jwk.js';
import { isObject } from './json.js';
import { Key } from './key.js';

export interface JWKS {
  keys: JWK[];
}

/** A collection of keys, usually loaded from a JWKS. */
export class KeySet {
  readonly #keys: Key[];

  constructor(keys: Iterable<Key> = []) {
    this.#keys = [...keys];
  }

  /** Loads a JWKS object or JSON string. Entries with an unsupported `kty` or `crv` are skipped. */
  static fromJSON(jwks: JWKS | string): KeySet {
    let parsed: unknown = jwks;
    if (typeof jwks === 'string') {
      try {
        parsed = JSON.parse(jwks);
      } catch {
        throw new InvalidKeyError('JWKS is not valid JSON');
      }
    }
    if (!isObject(parsed) || !Array.isArray(parsed.keys)) throw new InvalidKeyError('JWKS needs a keys array');

    const set = new KeySet();
    for (const entry of parsed.keys) {
      const jwk = parseJWK(entry);
      if (isSupportedJWK(jwk)) set.add(Key.fromJWK(jwk));
    }
    return set;
  }

  add(key: Key): this {
    this.#keys.push(key);
    return this;
  }

  get(kid: string): Key | undefined {
    return this.#keys.find((key) => key.kid === kid);
  }

  get keys(): readonly Key[] {
    return [...this.#keys];
  }

  /** Exports a JWKS. Without `includePrivate`, symmetric keys are left out and others are public only. */
  toJSON(includePrivate = false): JWKS {
    return {
      keys: this.#keys
        .filter((key) => includePrivate || key.type !== 'oct')
        .map((key) => key.toJWK(includePrivate)),
    };
  }
}
