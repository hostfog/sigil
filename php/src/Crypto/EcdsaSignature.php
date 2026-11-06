<?php

declare(strict_types=1);

namespace HostFog\Sigil\Crypto;

use HostFog\Sigil\Encoding\Der;
use UnexpectedValueException;

/**
 * Converts between OpenSSL's DER ECDSA signatures and the fixed-length r || s form used by JWS.
 *
 * @internal
 */
final class EcdsaSignature
{
    public static function fromDer(string $der, int $size): string
    {
        $integers = Der::readIntegerSequence($der);
        if (count($integers) !== 2) {
            throw new UnexpectedValueException('An ECDSA signature has exactly two integers.');
        }

        return str_pad($integers[0], $size, "\0", STR_PAD_LEFT) . str_pad($integers[1], $size, "\0", STR_PAD_LEFT);
    }

    public static function toDer(string $raw): string
    {
        $size = intdiv(strlen($raw), 2);

        return Der::sequence(Der::integer(substr($raw, 0, $size)), Der::integer(substr($raw, $size)));
    }
}
