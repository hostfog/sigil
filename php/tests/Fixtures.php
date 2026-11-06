<?php

declare(strict_types=1);

namespace HostFog\Sigil\Tests;

use HostFog\Sigil\Key;
use HostFog\Sigil\KeySet;

final class Fixtures
{
    public const NOW = 1800000000;

    public static function path(string $file): string
    {
        return dirname(__DIR__, 2) . '/testdata/' . $file;
    }

    /**
     * @return array<string, mixed>
     */
    public static function json(string $file): array
    {
        return json_decode((string) file_get_contents(self::path($file)), true, 512, JSON_THROW_ON_ERROR);
    }

    public static function keys(): KeySet
    {
        return KeySet::fromJson(self::json('keys.json'));
    }

    public static function key(string $kid): Key
    {
        return self::keys()->get($kid) ?? throw new \LogicException("No fixture key $kid.");
    }

    /**
     * @return array<string, string>
     */
    public static function jwk(string $kid): array
    {
        foreach (self::json('keys.json')['keys'] as $jwk) {
            if ($jwk['kid'] === $kid) {
                return $jwk;
            }
        }

        throw new \LogicException("No fixture key $kid.");
    }

    /**
     * @return array<string, mixed>
     */
    public static function claims(): array
    {
        return self::json('interop.json')['claims'];
    }
}
