<?php

declare(strict_types=1);

namespace HostFog\Sigil\Jwt;

use HostFog\Sigil\Algorithm;
use HostFog\Sigil\Crypto\ContentCipher;
use HostFog\Sigil\Crypto\KeyManagement;
use HostFog\Sigil\Encoding\Base64Url;
use HostFog\Sigil\Encoding\Json;
use HostFog\Sigil\Exception\InvalidKeyException;
use HostFog\Sigil\Exception\InvalidSignatureException;
use HostFog\Sigil\Exception\MalformedTokenException;
use HostFog\Sigil\Exception\UnsupportedAlgorithmException;
use HostFog\Sigil\Key;
use HostFog\Sigil\KeySet;
use HostFog\Sigil\Token;

/**
 * @internal
 */
final class Jwe
{
    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $options
     */
    public static function encrypt(array $claims, Key $key, array $options): string
    {
        $alg = $options['alg'] ?? $key->alg();
        if (!in_array($alg, Algorithm::KEY_MANAGEMENT, true)) {
            throw new UnsupportedAlgorithmException('Encryption needs a JWE "alg".');
        }
        $enc = $options['enc'] ?? Algorithm::A256GCM;
        if (!in_array($enc, Algorithm::CONTENT_ENCRYPTION, true)) {
            throw new UnsupportedAlgorithmException('Not a JWE content encryption algorithm.');
        }
        KeyPolicy::check($key, $alg, false, $enc);

        $header = Header::build(['alg' => $alg, 'enc' => $enc], $options, $key);
        [$cek, $encryptedKey, $additions] = KeyManagement::wrap($alg, $enc, $key, $header);
        $encodedHeader = Base64Url::encode(Json::encode(array_merge($header, $additions)));

        [$iv, $ciphertext, $tag] = ContentCipher::encrypt($enc, $cek, Json::encode((object) $claims), $encodedHeader);

        return implode('.', [
            $encodedHeader,
            ...array_map(Base64Url::encode(...), [$encryptedKey, $iv, $ciphertext, $tag]),
        ]);
    }

    /**
     * @param array<string, mixed> $options
     */
    public static function decrypt(string $token, Key|KeySet $keys, array $options): Token
    {
        $segments = Compact::split($token, 5);
        $header = Compact::decodeObject($segments[0], 'header');
        [$encryptedKey, $iv, $ciphertext, $tag] = array_map(Compact::decode(...), array_slice($segments, 1));

        $alg = Header::check($header, Algorithm::KEY_MANAGEMENT, $options);
        $enc = $header['enc'] ?? null;
        if (!in_array($enc, Algorithm::CONTENT_ENCRYPTION, true)) {
            throw new UnsupportedAlgorithmException('The token content encryption is not supported.');
        }

        $candidates = KeySelector::candidates($keys, $header, $alg, true, $enc);
        $plaintext = null;
        foreach ($candidates as $key) {
            try {
                $cek = KeyManagement::unwrap($alg, $enc, $key, $encryptedKey, $header);
                $plaintext = ContentCipher::decrypt($enc, $cek, $iv, $ciphertext, $tag, $segments[0]);
                break;
            } catch (InvalidSignatureException | InvalidKeyException $e) {
                // Without a "kid" every suitable key is tried; a single key reports its own failure.
                if (count($candidates) === 1) {
                    throw $e;
                }
            }
        }
        if ($plaintext === null) {
            throw new InvalidSignatureException('The token could not be decrypted.');
        }

        $claims = Json::decodeObject($plaintext)
            ?? throw new MalformedTokenException('The token payload is not a JSON object.');
        ClaimsValidator::validate($header, $claims, $options);

        return new Token($header, $claims);
    }
}
