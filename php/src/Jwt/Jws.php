<?php

declare(strict_types=1);

namespace HostFog\Sigil\Jwt;

use HostFog\Sigil\Algorithm;
use HostFog\Sigil\Crypto\Signer;
use HostFog\Sigil\Encoding\Base64Url;
use HostFog\Sigil\Encoding\Json;
use HostFog\Sigil\Exception\InvalidSignatureException;
use HostFog\Sigil\Exception\UnsupportedAlgorithmException;
use HostFog\Sigil\Key;
use HostFog\Sigil\KeySet;
use HostFog\Sigil\Token;

/**
 * @internal
 */
final class Jws
{
    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $options
     */
    public static function sign(array $claims, Key $key, array $options): string
    {
        $alg = $options['alg'] ?? $key->alg() ?? self::defaultAlgorithm($key);
        if (!in_array($alg, Algorithm::SIGNATURE, true)) {
            throw new UnsupportedAlgorithmException('Not a JWS algorithm.');
        }
        KeyPolicy::check($key, $alg, true);

        $header = Header::build(['alg' => $alg], $options, $key);
        $input = Base64Url::encode(Json::encode($header)) . '.' . Base64Url::encode(Json::encode((object) $claims));

        return $input . '.' . Base64Url::encode(Signer::sign($alg, $key, $input));
    }

    /**
     * @param array<string, mixed> $options
     */
    public static function verify(string $token, Key|KeySet $keys, array $options): Token
    {
        [$encodedHeader, $encodedPayload, $encodedSignature] = Compact::split($token, 3);
        $header = Compact::decodeObject($encodedHeader, 'header');
        $claims = Compact::decodeObject($encodedPayload, 'payload');
        $signature = Compact::decode($encodedSignature);

        $alg = Header::check($header, Algorithm::SIGNATURE, $options);
        $input = "$encodedHeader.$encodedPayload";

        $verified = false;
        foreach (KeySelector::candidates($keys, $header, $alg, false) as $key) {
            if (Signer::verify($alg, $key, $input, $signature)) {
                $verified = true;
                break;
            }
        }
        if (!$verified) {
            throw new InvalidSignatureException('The token signature is invalid.');
        }

        ClaimsValidator::validate($header, $claims, $options);

        return new Token($header, $claims);
    }

    public static function decode(string $token): Token
    {
        [$encodedHeader, $encodedPayload] = Compact::split($token, 3);

        return new Token(
            Compact::decodeObject($encodedHeader, 'header'),
            Compact::decodeObject($encodedPayload, 'payload'),
        );
    }

    private static function defaultAlgorithm(Key $key): string
    {
        if ($key->type() === 'oct') {
            return Algorithm::HS256;
        }
        if ($key->type() === 'RSA') {
            return Algorithm::RS256;
        }

        return match ($key->curve()) {
            'P-256' => Algorithm::ES256,
            'P-384' => Algorithm::ES384,
            'P-521' => Algorithm::ES512,
            'Ed25519' => Algorithm::EDDSA,
            default => throw new UnsupportedAlgorithmException('No signing algorithm suits this key.'),
        };
    }
}
