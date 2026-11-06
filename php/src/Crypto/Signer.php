<?php

declare(strict_types=1);

namespace HostFog\Sigil\Crypto;

use HostFog\Sigil\Exception\InvalidKeyException;
use HostFog\Sigil\Key;

/**
 * Creates and checks JWS signatures. Callers must have checked that the key suits the algorithm.
 *
 * @internal
 */
final class Signer
{
    public static function sign(string $alg, Key $key, string $input): string
    {
        return match (substr($alg, 0, 2)) {
            'HS' => hash_hmac(self::hash($alg), $input, (string) $key->material('k'), true),
            'RS' => self::opensslSign($key, $input, self::hash($alg)),
            'PS' => RsaPss::sign($key, self::hash($alg), $input),
            'ES' => EcdsaSignature::fromDer(self::opensslSign($key, $input, self::hash($alg)), self::ecSize($key)),
            'Ed' => sodium_crypto_sign_detached($input, self::ed25519SecretKey($key)),
        };
    }

    public static function verify(string $alg, Key $key, string $input, string $signature): bool
    {
        return match (substr($alg, 0, 2)) {
            'HS' => hash_equals(self::sign($alg, $key, $input), $signature),
            'RS' => self::opensslVerify($key, $input, $signature, self::hash($alg)),
            'PS' => RsaPss::verify($key, self::hash($alg), $input, $signature),
            'ES' => strlen($signature) === 2 * self::ecSize($key)
                && self::opensslVerify($key, $input, EcdsaSignature::toDer($signature), self::hash($alg)),
            'Ed' => strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES
                && sodium_crypto_sign_verify_detached($signature, $input, (string) $key->material('x')),
        };
    }

    private static function hash(string $alg): string
    {
        return 'sha' . substr($alg, 2);
    }

    private static function ecSize(Key $key): int
    {
        return (int) OpenSslKey::coordinateSize((string) $key->curve());
    }

    private static function opensslSign(Key $key, string $input, string $hash): string
    {
        if (!openssl_sign($input, $signature, $key->openSslPrivateKey(), $hash)) {
            throw new InvalidKeyException('Signing failed.');
        }

        return $signature;
    }

    private static function opensslVerify(Key $key, string $input, string $signature, string $hash): bool
    {
        return openssl_verify($input, $signature, $key->openSslPublicKey(), $hash) === 1;
    }

    private static function ed25519SecretKey(Key $key): string
    {
        return sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair((string) $key->material('d')));
    }
}
