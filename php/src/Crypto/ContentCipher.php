<?php

declare(strict_types=1);

namespace HostFog\Sigil\Crypto;

use HostFog\Sigil\Exception\InvalidSignatureException;

/**
 * JWE content encryption: AES-GCM and AES-CBC with HMAC-SHA2 (RFC 7518 §5).
 *
 * @internal
 */
final class ContentCipher
{
    private const KEY_LENGTHS = [
        'A128GCM' => 16,
        'A192GCM' => 24,
        'A256GCM' => 32,
        'A128CBC-HS256' => 32,
        'A192CBC-HS384' => 48,
        'A256CBC-HS512' => 64,
    ];

    private const GCM_IV_LENGTH = 12;
    private const GCM_TAG_LENGTH = 16;
    private const CBC_IV_LENGTH = 16;

    public static function keyLength(string $enc): int
    {
        return self::KEY_LENGTHS[$enc];
    }

    /**
     * @return array{string, string, string} iv, ciphertext, tag
     */
    public static function encrypt(string $enc, string $key, string $plaintext, string $aad): array
    {
        if (self::isGcm($enc)) {
            $iv = random_bytes(self::GCM_IV_LENGTH);
            $tag = '';
            $ciphertext = openssl_encrypt(
                $plaintext,
                self::gcmCipher($key),
                $key,
                OPENSSL_RAW_DATA,
                $iv,
                $tag,
                $aad,
                self::GCM_TAG_LENGTH,
            );

            return [$iv, $ciphertext, $tag];
        }

        [$macKey, $encKey] = str_split($key, intdiv(strlen($key), 2));
        $iv = random_bytes(self::CBC_IV_LENGTH);
        $ciphertext = openssl_encrypt($plaintext, self::cbcCipher($encKey), $encKey, OPENSSL_RAW_DATA, $iv);

        return [$iv, $ciphertext, self::cbcTag($enc, $macKey, $aad, $iv, $ciphertext)];
    }

    public static function decrypt(
        string $enc,
        string $key,
        string $iv,
        string $ciphertext,
        string $tag,
        string $aad,
    ): string {
        if (self::isGcm($enc)) {
            $plaintext = strlen($iv) === self::GCM_IV_LENGTH && strlen($tag) === self::GCM_TAG_LENGTH
                ? openssl_decrypt($ciphertext, self::gcmCipher($key), $key, OPENSSL_RAW_DATA, $iv, $tag, $aad)
                : false;
        } else {
            [$macKey, $encKey] = str_split($key, intdiv(strlen($key), 2));
            $plaintext = strlen($iv) === self::CBC_IV_LENGTH
                && hash_equals(self::cbcTag($enc, $macKey, $aad, $iv, $ciphertext), $tag)
                ? openssl_decrypt($ciphertext, self::cbcCipher($encKey), $encKey, OPENSSL_RAW_DATA, $iv)
                : false;
        }

        if ($plaintext === false) {
            throw new InvalidSignatureException('Decryption failed.');
        }

        return $plaintext;
    }

    private static function isGcm(string $enc): bool
    {
        return str_ends_with($enc, 'GCM');
    }

    private static function gcmCipher(string $key): string
    {
        return 'aes-' . (strlen($key) * 8) . '-gcm';
    }

    private static function cbcCipher(string $key): string
    {
        return 'aes-' . (strlen($key) * 8) . '-cbc';
    }

    private static function cbcTag(string $enc, string $macKey, string $aad, string $iv, string $ciphertext): string
    {
        $input = $aad . $iv . $ciphertext . pack('J', strlen($aad) * 8);
        $mac = hash_hmac('sha' . substr($enc, -3), $input, $macKey, true);

        return substr($mac, 0, strlen($macKey));
    }
}
