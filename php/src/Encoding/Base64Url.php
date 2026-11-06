<?php

declare(strict_types=1);

namespace HostFog\Sigil\Encoding;

/**
 * @internal
 */
final class Base64Url
{
    public static function encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Strict decoding: anything that does not re-encode to the same text (padding, the
     * standard alphabet, whitespace, stray bits) is rejected with null.
     */
    public static function decode(string $data): ?string
    {
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false || self::encode($decoded) !== $data) {
            return null;
        }

        return $decoded;
    }
}
