<?php

declare(strict_types=1);

namespace HostFog\Sigil\Jwt;

use HostFog\Sigil\Exception\MalformedTokenException;
use HostFog\Sigil\Exception\UnsupportedAlgorithmException;
use HostFog\Sigil\Key;

/**
 * @internal
 */
final class Header
{
    private const RESERVED = ['alg', 'enc', 'zip', 'crit'];

    /**
     * @param array<string, string> $algorithms alg, and enc for JWE
     * @param array<string, mixed> $options
     *
     * @return array<string, mixed>
     */
    public static function build(array $algorithms, array $options, Key $key): array
    {
        $header = $algorithms + ['typ' => $options['typ'] ?? 'JWT'];

        $kid = $options['kid'] ?? $key->kid();
        if ($kid !== null) {
            $header['kid'] = $kid;
        }

        $extra = array_diff_key($options['headers'] ?? [], array_flip(self::RESERVED));

        return array_merge($header, $extra);
    }

    /**
     * Header checks made before any key is touched. Returns the token's "alg".
     *
     * @param array<string, mixed> $header
     * @param list<string> $supported
     * @param array<string, mixed> $options
     */
    public static function check(array $header, array $supported, array $options): string
    {
        $alg = $header['alg'] ?? null;
        if (!is_string($alg)) {
            throw new MalformedTokenException('The token header has no "alg".');
        }
        if (isset($header['kid']) && !is_string($header['kid'])) {
            throw new MalformedTokenException('The token "kid" must be a string.');
        }

        if (!in_array($alg, $supported, true)) {
            throw new UnsupportedAlgorithmException('The token algorithm is not supported.');
        }
        if (isset($options['algorithms']) && !in_array($alg, (array) $options['algorithms'], true)) {
            throw new UnsupportedAlgorithmException('The token algorithm is not allowed.');
        }

        if (array_key_exists('crit', $header)) {
            throw new UnsupportedAlgorithmException('Critical header extensions are not supported.');
        }
        if (array_key_exists('zip', $header)) {
            throw new UnsupportedAlgorithmException('Compressed tokens are not supported.');
        }

        return $alg;
    }
}
