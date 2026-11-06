<?php

declare(strict_types=1);

namespace HostFog\Sigil\Jwt;

use HostFog\Sigil\Algorithm;
use HostFog\Sigil\Crypto\AesKeyWrap;
use HostFog\Sigil\Crypto\ContentCipher;
use HostFog\Sigil\Exception\InvalidKeyException;
use HostFog\Sigil\Key;

/**
 * Decides whether a key may be used with an algorithm.
 *
 * @internal
 */
final class KeyPolicy
{
    private const HMAC_MIN_LENGTHS = [
        Algorithm::HS256 => 32,
        Algorithm::HS384 => 48,
        Algorithm::HS512 => 64,
    ];

    private const ECDH_CURVES = ['P-256', 'P-384', 'P-521', 'X25519'];

    /**
     * @param string|null $enc content encryption, needed to size "dir" keys
     */
    public static function check(Key $key, string $alg, bool $needsPrivate, ?string $enc = null): void
    {
        if ($key->alg() !== null && $key->alg() !== $alg) {
            throw new InvalidKeyException("The key is meant for {$key->alg()}, not $alg.");
        }
        if (!self::matchesType($key, $alg)) {
            throw new InvalidKeyException("The key type does not match $alg.");
        }

        if ($key->type() === 'oct') {
            self::checkSecretLength(strlen((string) $key->material('k')), $alg, $enc);
        } elseif ($needsPrivate && !$key->isPrivate()) {
            throw new InvalidKeyException("$alg needs a private key.");
        }
    }

    public static function allows(Key $key, string $alg, bool $needsPrivate, ?string $enc = null): bool
    {
        try {
            self::check($key, $alg, $needsPrivate, $enc);
        } catch (InvalidKeyException) {
            return false;
        }

        return true;
    }

    private static function matchesType(Key $key, string $alg): bool
    {
        return match ($alg) {
            Algorithm::HS256, Algorithm::HS384, Algorithm::HS512,
            Algorithm::DIR, Algorithm::A128KW, Algorithm::A192KW, Algorithm::A256KW => $key->type() === 'oct',
            Algorithm::RS256, Algorithm::RS384, Algorithm::RS512,
            Algorithm::PS256, Algorithm::PS384, Algorithm::PS512,
            Algorithm::RSA_OAEP, Algorithm::RSA_OAEP_256 => $key->type() === 'RSA',
            Algorithm::ES256 => $key->curve() === 'P-256',
            Algorithm::ES384 => $key->curve() === 'P-384',
            Algorithm::ES512 => $key->curve() === 'P-521',
            Algorithm::EDDSA => $key->curve() === 'Ed25519',
            Algorithm::ECDH_ES, Algorithm::ECDH_ES_A128KW,
            Algorithm::ECDH_ES_A192KW, Algorithm::ECDH_ES_A256KW => in_array($key->curve(), self::ECDH_CURVES, true),
            default => false,
        };
    }

    private static function checkSecretLength(int $length, string $alg, ?string $enc): void
    {
        if (isset(self::HMAC_MIN_LENGTHS[$alg])) {
            if ($length < self::HMAC_MIN_LENGTHS[$alg]) {
                throw new InvalidKeyException(
                    sprintf('%s keys must be at least %d bytes.', $alg, self::HMAC_MIN_LENGTHS[$alg]),
                );
            }

            return;
        }

        $expected = $alg === Algorithm::DIR ? ContentCipher::keyLength((string) $enc) : AesKeyWrap::kekLength($alg);
        if ($length !== $expected) {
            throw new InvalidKeyException(sprintf('%s needs a key of exactly %d bytes.', $alg, $expected));
        }
    }
}
