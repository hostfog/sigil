<?php

declare(strict_types=1);

namespace HostFog\Sigil\Crypto;

use HostFog\Sigil\Key;

/**
 * Raw RSA, used where PHP's OpenSSL binding has no matching padding mode (PSS, OAEP with SHA-256).
 *
 * @internal
 */
final class Rsa
{
    public static function bitLength(string $modulus): int
    {
        $modulus = ltrim($modulus, "\0");
        if ($modulus === '') {
            return 0;
        }

        return (strlen($modulus) - 1) * 8 + strlen(decbin(ord($modulus[0])));
    }

    public static function modulusLength(Key $key): int
    {
        return intdiv(self::bitLength((string) $key->material('n')) + 7, 8);
    }

    /**
     * Computes input^d mod n. The input must be exactly modulus length.
     */
    public static function privateOperation(Key $key, string $input): ?string
    {
        return openssl_private_decrypt($input, $output, $key->openSslPrivateKey(), OPENSSL_NO_PADDING) ? $output : null;
    }

    /**
     * Computes input^e mod n. The input must be exactly modulus length.
     */
    public static function publicOperation(Key $key, string $input): ?string
    {
        return openssl_public_encrypt($input, $output, $key->openSslPublicKey(), OPENSSL_NO_PADDING) ? $output : null;
    }

    public static function mgf1(string $seed, int $length, string $hash): string
    {
        $mask = '';
        for ($counter = 0; strlen($mask) < $length; $counter++) {
            $mask .= hash($hash, $seed . pack('N', $counter), true);
        }

        return substr($mask, 0, $length);
    }
}
