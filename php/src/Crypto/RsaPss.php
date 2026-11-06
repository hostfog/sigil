<?php

declare(strict_types=1);

namespace HostFog\Sigil\Crypto;

use HostFog\Sigil\Exception\InvalidKeyException;
use HostFog\Sigil\Key;

/**
 * RSASSA-PSS (RFC 8017 §8.1) with MGF1 on the same hash and a salt as long as the hash.
 *
 * @internal
 */
final class RsaPss
{
    public static function sign(Key $key, string $hash, string $message): string
    {
        $emBits = Rsa::bitLength((string) $key->material('n')) - 1;
        $emLength = intdiv($emBits + 7, 8);
        $hashLength = strlen(hash($hash, '', true));

        $salt = random_bytes($hashLength);
        $h = hash($hash, str_repeat("\0", 8) . hash($hash, $message, true) . $salt, true);
        $db = str_repeat("\0", $emLength - 2 * $hashLength - 2) . "\x01" . $salt;
        $maskedDb = self::clearTopBits($db ^ Rsa::mgf1($h, strlen($db), $hash), $emLength, $emBits);

        $encoded = str_pad($maskedDb . $h . "\xbc", Rsa::modulusLength($key), "\0", STR_PAD_LEFT);

        return Rsa::privateOperation($key, $encoded) ?? throw new InvalidKeyException('RSA signing failed.');
    }

    public static function verify(Key $key, string $hash, string $message, string $signature): bool
    {
        $modulusLength = Rsa::modulusLength($key);
        if (strlen($signature) !== $modulusLength) {
            return false;
        }

        $encoded = Rsa::publicOperation($key, $signature);
        if ($encoded === null) {
            return false;
        }

        $emBits = Rsa::bitLength((string) $key->material('n')) - 1;
        $emLength = intdiv($emBits + 7, 8);
        $hashLength = strlen(hash($hash, '', true));

        // The encoded message is one byte shorter than the modulus when emBits is a multiple of 8.
        if (ltrim(substr($encoded, 0, $modulusLength - $emLength), "\0") !== '') {
            return false;
        }
        $encoded = substr($encoded, $modulusLength - $emLength);
        if ($encoded[$emLength - 1] !== "\xbc") {
            return false;
        }

        $maskedDb = substr($encoded, 0, $emLength - $hashLength - 1);
        $h = substr($encoded, $emLength - $hashLength - 1, $hashLength);
        if (self::clearTopBits($maskedDb, $emLength, $emBits) !== $maskedDb) {
            return false;
        }

        $db = self::clearTopBits($maskedDb ^ Rsa::mgf1($h, strlen($maskedDb), $hash), $emLength, $emBits);
        $padding = strlen($db) - $hashLength - 1;
        if ($padding < 0 || ltrim(substr($db, 0, $padding), "\0") !== '' || $db[$padding] !== "\x01") {
            return false;
        }

        $salt = substr($db, $padding + 1);
        $expected = hash($hash, str_repeat("\0", 8) . hash($hash, $message, true) . $salt, true);

        return hash_equals($expected, $h);
    }

    private static function clearTopBits(string $maskedDb, int $emLength, int $emBits): string
    {
        $maskedDb[0] = chr(ord($maskedDb[0]) & (0xff >> (8 * $emLength - $emBits)));

        return $maskedDb;
    }
}
