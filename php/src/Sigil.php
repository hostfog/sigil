<?php

declare(strict_types=1);

namespace HostFog\Sigil;

use HostFog\Sigil\Jwt\Jwe;
use HostFog\Sigil\Jwt\Jws;

final class Sigil
{
    /**
     * @param array<string, mixed> $claims
     * @param array{alg?: string, kid?: string, typ?: string, headers?: array<string, mixed>} $options
     */
    public static function sign(array $claims, Key $key, array $options = []): string
    {
        return Jws::sign($claims, $key, $options);
    }

    /**
     * @param array{
     *     algorithms?: list<string>,
     *     issuer?: string|list<string>,
     *     audience?: string|list<string>,
     *     subject?: string,
     *     typ?: string,
     *     leeway?: int,
     *     maxAge?: int,
     *     required?: list<string>,
     *     now?: int,
     * } $options
     */
    public static function verify(string $token, Key|KeySet $keys, array $options = []): Token
    {
        return Jws::verify($token, $keys, $options);
    }

    /**
     * @param array<string, mixed> $claims
     * @param array{alg?: string, enc?: string, kid?: string, typ?: string, headers?: array<string, mixed>} $options
     */
    public static function encrypt(array $claims, Key $key, array $options = []): string
    {
        return Jwe::encrypt($claims, $key, $options);
    }

    /**
     * @param array{
     *     algorithms?: list<string>,
     *     issuer?: string|list<string>,
     *     audience?: string|list<string>,
     *     subject?: string,
     *     typ?: string,
     *     leeway?: int,
     *     maxAge?: int,
     *     required?: list<string>,
     *     now?: int,
     * } $options
     */
    public static function decrypt(string $token, Key|KeySet $keys, array $options = []): Token
    {
        return Jwe::decrypt($token, $keys, $options);
    }

    /**
     * Reads a signed token without verifying anything.
     */
    public static function decode(string $token): Token
    {
        return Jws::decode($token);
    }

    private function __construct()
    {
    }
}
