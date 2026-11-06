<?php

declare(strict_types=1);

namespace HostFog\Sigil\Jwt;

use HostFog\Sigil\Exception\InvalidClaimException;
use HostFog\Sigil\Exception\TokenExpiredException;
use HostFog\Sigil\Exception\TokenNotYetValidException;

/**
 * @internal
 */
final class ClaimsValidator
{
    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $options
     */
    public static function validate(array $header, array $claims, array $options): void
    {
        foreach (['exp', 'nbf', 'iat'] as $name) {
            if (array_key_exists($name, $claims) && !is_int($claims[$name]) && !is_float($claims[$name])) {
                throw new InvalidClaimException($name, "The \"$name\" claim must be a number.");
            }
        }

        foreach ($options['required'] ?? [] as $name) {
            if (!array_key_exists($name, $claims)) {
                throw new InvalidClaimException($name, "The \"$name\" claim is required.");
            }
        }

        self::checkTimes($claims, $options['now'] ?? time(), $options['leeway'] ?? 0, $options['maxAge'] ?? null);
        self::checkValues($header, $claims, $options);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function checkTimes(array $claims, int|float $now, int|float $leeway, int|float|null $maxAge): void
    {
        if (isset($claims['exp']) && $now >= $claims['exp'] + $leeway) {
            throw new TokenExpiredException('The token has expired.');
        }
        if (isset($claims['nbf']) && $now < $claims['nbf'] - $leeway) {
            throw new TokenNotYetValidException('The token is not valid yet.');
        }
        if (isset($claims['iat']) && $claims['iat'] > $now + $leeway) {
            throw new InvalidClaimException('iat', 'The token was issued in the future.');
        }

        if ($maxAge !== null) {
            if (!isset($claims['iat'])) {
                throw new InvalidClaimException('iat', 'The "iat" claim is required when a maximum age is set.');
            }
            if ($now - $claims['iat'] > $maxAge + $leeway) {
                throw new TokenExpiredException('The token is older than the maximum age.');
            }
        }
    }

    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $options
     */
    private static function checkValues(array $header, array $claims, array $options): void
    {
        if (isset($options['issuer']) && !in_array($claims['iss'] ?? null, (array) $options['issuer'], true)) {
            throw new InvalidClaimException('iss', 'The token issuer is not accepted.');
        }

        if (isset($options['audience'])) {
            $audience = (array) ($claims['aud'] ?? []);
            $accepted = array_filter((array) $options['audience'], static fn ($aud) => in_array($aud, $audience, true));
            if ($accepted === []) {
                throw new InvalidClaimException('aud', 'The token audience is not accepted.');
            }
        }

        if (isset($options['subject']) && ($claims['sub'] ?? null) !== $options['subject']) {
            throw new InvalidClaimException('sub', 'The token subject is not accepted.');
        }

        if (isset($options['typ'])) {
            $typ = $header['typ'] ?? null;
            if (!is_string($typ) || strcasecmp($typ, $options['typ']) !== 0) {
                throw new InvalidClaimException('typ', 'The token type is not accepted.');
            }
        }
    }
}
