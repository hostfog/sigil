<?php

declare(strict_types=1);

namespace HostFog\Sigil\Crypto;

use HostFog\Sigil\Exception\InvalidSignatureException;

/**
 * AES key wrap, RFC 3394.
 *
 * @internal
 */
final class AesKeyWrap
{
    private const IV = "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6";

    /**
     * Key encryption key length for A128KW, ECDH-ES+A192KW and the like.
     */
    public static function kekLength(string $alg): int
    {
        return intdiv((int) substr($alg, -5, 3), 8);
    }

    public static function wrap(string $kek, string $key): string
    {
        $blocks = str_split($key, 8);
        $count = count($blocks);
        $a = self::IV;

        for ($j = 0; $j < 6; $j++) {
            for ($i = 0; $i < $count; $i++) {
                $b = self::aes($kek, $a . $blocks[$i], true);
                $a = substr($b, 0, 8) ^ pack('J', $count * $j + $i + 1);
                $blocks[$i] = substr($b, 8);
            }
        }

        return $a . implode('', $blocks);
    }

    public static function unwrap(string $kek, string $wrapped): string
    {
        if (strlen($wrapped) < 24 || strlen($wrapped) % 8 !== 0) {
            throw new InvalidSignatureException('Invalid wrapped key.');
        }

        $blocks = str_split(substr($wrapped, 8), 8);
        $count = count($blocks);
        $a = substr($wrapped, 0, 8);

        for ($j = 5; $j >= 0; $j--) {
            for ($i = $count - 1; $i >= 0; $i--) {
                $b = self::aes($kek, ($a ^ pack('J', $count * $j + $i + 1)) . $blocks[$i], false);
                $a = substr($b, 0, 8);
                $blocks[$i] = substr($b, 8);
            }
        }

        if (!hash_equals(self::IV, $a)) {
            throw new InvalidSignatureException('Key unwrap failed.');
        }

        return implode('', $blocks);
    }

    private static function aes(string $kek, string $block, bool $encrypt): string
    {
        $cipher = 'aes-' . (strlen($kek) * 8) . '-ecb';
        $options = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;

        return $encrypt
            ? openssl_encrypt($block, $cipher, $kek, $options)
            : openssl_decrypt($block, $cipher, $kek, $options);
    }
}
