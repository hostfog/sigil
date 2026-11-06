<?php

declare(strict_types=1);

namespace HostFog\Sigil\Jwt;

use HostFog\Sigil\Encoding\Base64Url;
use HostFog\Sigil\Encoding\Json;
use HostFog\Sigil\Exception\MalformedTokenException;

/**
 * Reading compact serialization segments.
 *
 * @internal
 */
final class Compact
{
    /**
     * @return list<string>
     */
    public static function split(string $token, int $count): array
    {
        $segments = explode('.', $token);
        if (count($segments) !== $count) {
            throw new MalformedTokenException("Expected a token with $count segments.");
        }

        return $segments;
    }

    public static function decode(string $segment): string
    {
        return Base64Url::decode($segment) ?? throw new MalformedTokenException('A token segment is not base64url.');
    }

    /**
     * @return array<string, mixed>
     */
    public static function decodeObject(string $segment, string $name): array
    {
        return Json::decodeObject(self::decode($segment))
            ?? throw new MalformedTokenException("The token $name is not a JSON object.");
    }
}
