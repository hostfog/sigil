<?php

declare(strict_types=1);

namespace HostFog\Sigil\Encoding;

use JsonException;

/**
 * @internal
 */
final class Json
{
    public static function encode(mixed $value): string
    {
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    /**
     * Decodes a JSON object into an associative array. Returns null for anything else.
     *
     * @return array<string, mixed>|null
     */
    public static function decodeObject(string $json): ?array
    {
        // Both "{}" and "[]" decode to an empty PHP array, so check the raw text.
        if (!str_starts_with(ltrim($json, " \t\n\r"), '{')) {
            return null;
        }

        try {
            $value = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }

        return is_array($value) ? $value : null;
    }
}
