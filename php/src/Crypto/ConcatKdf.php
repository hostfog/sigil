<?php

declare(strict_types=1);

namespace HostFog\Sigil\Crypto;

/**
 * Concat KDF with SHA-256 as profiled by RFC 7518 §4.6.2.
 *
 * @internal
 */
final class ConcatKdf
{
    public static function derive(string $secret, string $algorithmId, int $length, string $apu, string $apv): string
    {
        $otherInfo = self::lengthPrefixed($algorithmId)
            . self::lengthPrefixed($apu)
            . self::lengthPrefixed($apv)
            . pack('N', $length * 8);

        $output = '';
        for ($counter = 1; strlen($output) < $length; $counter++) {
            $output .= hash('sha256', pack('N', $counter) . $secret . $otherInfo, true);
        }

        return substr($output, 0, $length);
    }

    private static function lengthPrefixed(string $data): string
    {
        return pack('N', strlen($data)) . $data;
    }
}
