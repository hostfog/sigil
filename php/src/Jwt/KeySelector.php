<?php

declare(strict_types=1);

namespace HostFog\Sigil\Jwt;

use HostFog\Sigil\Exception\KeyNotFoundException;
use HostFog\Sigil\Key;
use HostFog\Sigil\KeySet;

/**
 * @internal
 */
final class KeySelector
{
    /**
     * Keys to try, in order. With a "kid" header only that key is used.
     *
     * @param array<string, mixed> $header
     *
     * @return list<Key>
     */
    public static function candidates(
        Key|KeySet $keys,
        array $header,
        string $alg,
        bool $needsPrivate,
        ?string $enc = null,
    ): array {
        if ($keys instanceof Key) {
            KeyPolicy::check($keys, $alg, $needsPrivate, $enc);

            return [$keys];
        }

        if (isset($header['kid'])) {
            $key = $keys->get($header['kid']) ?? throw new KeyNotFoundException('No key matches the token "kid".');
            KeyPolicy::check($key, $alg, $needsPrivate, $enc);

            return [$key];
        }

        $matching = array_values(array_filter(
            $keys->keys(),
            static fn (Key $key): bool => KeyPolicy::allows($key, $alg, $needsPrivate, $enc),
        ));
        if ($matching === []) {
            throw new KeyNotFoundException("No key in the set can be used with $alg.");
        }

        return $matching;
    }
}
