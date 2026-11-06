<?php

declare(strict_types=1);

namespace HostFog\Sigil\Crypto;

use HostFog\Sigil\Exception\InvalidKeyException;
use HostFog\Sigil\Key;

/**
 * RSAES-OAEP (RFC 8017 §7.1) with an empty label and MGF1 on the same hash.
 *
 * @internal
 */
final class RsaOaep
{
    public static function encrypt(Key $key, string $hash, string $message): string
    {
        $length = Rsa::modulusLength($key);
        $hashLength = strlen(hash($hash, '', true));
        $padding = $length - strlen($message) - 2 * $hashLength - 2;
        if ($padding < 0) {
            throw new InvalidKeyException('The RSA key is too small for this message.');
        }

        $db = hash($hash, '', true) . str_repeat("\0", $padding) . "\x01" . $message;
        $seed = random_bytes($hashLength);
        $maskedDb = $db ^ Rsa::mgf1($seed, strlen($db), $hash);
        $maskedSeed = $seed ^ Rsa::mgf1($maskedDb, $hashLength, $hash);

        return Rsa::publicOperation($key, "\0" . $maskedSeed . $maskedDb)
            ?? throw new InvalidKeyException('RSA encryption failed.');
    }

    public static function decrypt(Key $key, string $hash, string $ciphertext): ?string
    {
        $length = Rsa::modulusLength($key);
        $hashLength = strlen(hash($hash, '', true));
        if (strlen($ciphertext) !== $length || $length < 2 * $hashLength + 2) {
            return null;
        }

        $encoded = Rsa::privateOperation($key, $ciphertext);
        if ($encoded === null) {
            return null;
        }

        $maskedDb = substr($encoded, 1 + $hashLength);
        $seed = substr($encoded, 1, $hashLength) ^ Rsa::mgf1($maskedDb, $hashLength, $hash);
        $db = $maskedDb ^ Rsa::mgf1($seed, strlen($maskedDb), $hash);

        // Scan the whole padding without branching on its contents, so failures take the same time.
        $invalid = ord($encoded[0]) | (int) !hash_equals(hash($hash, '', true), substr($db, 0, $hashLength));
        $searching = 1;
        $separator = 0;
        for ($i = $hashLength; $i < strlen($db); $i++) {
            $byte = ord($db[$i]);
            $isZero = (($byte - 1) >> 8) & 1;
            $isOne = ((($byte ^ 1) - 1) >> 8) & 1;
            $separator |= ($searching & $isOne) * $i;
            $invalid |= $searching & (($isZero | $isOne) ^ 1);
            $searching &= $isOne ^ 1;
        }

        if (($invalid | $searching) !== 0) {
            return null;
        }

        return substr($db, $separator + 1);
    }
}
