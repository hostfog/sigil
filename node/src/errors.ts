export type ErrorCode =
  | 'malformed'
  | 'unsupported_alg'
  | 'invalid_key'
  | 'key_not_found'
  | 'invalid_signature'
  | 'expired'
  | 'not_yet_valid'
  | 'invalid_claim';

/** Base class for every error thrown by Sigil. `code` is stable across languages. */
export class SigilError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = new.target.name;
    this.code = code;
  }
}

export class MalformedTokenError extends SigilError {
  constructor(message = 'malformed token') {
    super('malformed', message);
  }
}

export class UnsupportedAlgorithmError extends SigilError {
  constructor(message = 'unsupported algorithm') {
    super('unsupported_alg', message);
  }
}

export class InvalidKeyError extends SigilError {
  constructor(message = 'invalid key') {
    super('invalid_key', message);
  }
}

export class KeyNotFoundError extends SigilError {
  constructor(message = 'no matching key') {
    super('key_not_found', message);
  }
}

/** Thrown for a bad JWS signature and for any JWE decryption failure. */
export class InvalidSignatureError extends SigilError {
  constructor(message = 'invalid signature') {
    super('invalid_signature', message);
  }
}

export class TokenExpiredError extends SigilError {
  constructor(message = 'token has expired') {
    super('expired', message);
  }
}

export class TokenNotYetValidError extends SigilError {
  constructor(message = 'token is not valid yet') {
    super('not_yet_valid', message);
  }
}

export class InvalidClaimError extends SigilError {
  readonly claim: string;

  constructor(claim: string, message = `invalid "${claim}" claim`) {
    super('invalid_claim', message);
    this.claim = claim;
  }
}
