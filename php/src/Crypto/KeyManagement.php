<?php

declare(strict_types=1);

namespace HostFog\Sigil\Crypto;

use HostFog\Sigil\Algorithm;
use HostFog\Sigil\Encoding\Base64Url;
use HostFog\Sigil\Exception\InvalidKeyException;
use HostFog\Sigil\Exception\InvalidSignatureException;
use HostFog\Sigil\Exception\MalformedTokenException;
use HostFog\Sigil\Key;
use SodiumException;

/**
 * Produces and recovers the JWE content encryption key. Callers must have checked that the key suits the algorithm.
 *
 * @internal
 */
final class KeyManagement
{
    /**
     * @param array<string, mixed> $header
     *
     * @return array{string, string, array<string, mixed>} content key, encrypted key, header additions
     */
    public static function wrap(string $alg, string $enc, Key $key, array $header): array
    {
        $cekLength = ContentCipher::keyLength($enc);

        if ($alg === Algorithm::DIR) {
            return [(string) $key->material('k'), '', []];
        }

        if (str_starts_with($alg, Algorithm::ECDH_ES)) {
            $ephemeral = Key::fromJwk(
                $key->type() === 'OKP' ? KeyGenerator::x25519() : KeyGenerator::ec((string) $key->curve()),
            );
            $derived = self::deriveKey($alg, $enc, $ephemeral, $key, $header);
            $additions = ['epk' => $ephemeral->publicKey()->toJwk()];

            if ($alg === Algorithm::ECDH_ES) {
                return [$derived, '', $additions];
            }

            $cek = random_bytes($cekLength);

            return [$cek, AesKeyWrap::wrap($derived, $cek), $additions];
        }

        $cek = random_bytes($cekLength);
        $encryptedKey = match ($alg) {
            Algorithm::RSA_OAEP => self::rsaOaepEncrypt($key, $cek),
            Algorithm::RSA_OAEP_256 => RsaOaep::encrypt($key, 'sha256', $cek),
            default => AesKeyWrap::wrap((string) $key->material('k'), $cek),
        };

        return [$cek, $encryptedKey, []];
    }

    /**
     * @param array<string, mixed> $header
     */
    public static function unwrap(string $alg, string $enc, Key $key, string $encryptedKey, array $header): string
    {
        if (($alg === Algorithm::DIR || $alg === Algorithm::ECDH_ES) && $encryptedKey !== '') {
            throw new MalformedTokenException("$alg tokens must have an empty encrypted key.");
        }

        if ($alg === Algorithm::DIR) {
            return (string) $key->material('k');
        }
        if ($alg === Algorithm::ECDH_ES) {
            return self::deriveKey($alg, $enc, $key, self::ephemeralKey($header, $key), $header);
        }
        if (str_starts_with($alg, 'RSA-OAEP')) {
            return self::rsaUnwrap($alg, $enc, $key, $encryptedKey);
        }

        $kek = str_starts_with($alg, Algorithm::ECDH_ES)
            ? self::deriveKey($alg, $enc, $key, self::ephemeralKey($header, $key), $header)
            : (string) $key->material('k');

        $cek = AesKeyWrap::unwrap($kek, $encryptedKey);
        if (strlen($cek) !== ContentCipher::keyLength($enc)) {
            throw new InvalidSignatureException('Decryption failed.');
        }

        return $cek;
    }

    private static function rsaUnwrap(string $alg, string $enc, Key $key, string $encryptedKey): string
    {
        $cek = $alg === Algorithm::RSA_OAEP
            ? self::rsaOaepDecrypt($key, $encryptedKey)
            : RsaOaep::decrypt($key, 'sha256', $encryptedKey);
        $cekLength = ContentCipher::keyLength($enc);

        // RFC 7516 §11.5: carry on with a random key so a padding failure looks like a bad tag.
        return $cek !== null && strlen($cek) === $cekLength ? $cek : random_bytes($cekLength);
    }

    /**
     * @param array<string, mixed> $header
     */
    private static function deriveKey(string $alg, string $enc, Key $private, Key $public, array $header): string
    {
        $direct = $alg === Algorithm::ECDH_ES;

        return ConcatKdf::derive(
            self::agree($private, $public),
            $direct ? $enc : $alg,
            $direct ? ContentCipher::keyLength($enc) : AesKeyWrap::kekLength($alg),
            self::partyInfo($header, 'apu'),
            self::partyInfo($header, 'apv'),
        );
    }

    private static function agree(Key $private, Key $public): string
    {
        if ($private->type() === 'OKP') {
            try {
                return sodium_crypto_scalarmult((string) $private->material('d'), (string) $public->material('x'));
            } catch (SodiumException) {
                throw new InvalidSignatureException('Decryption failed.');
            }
        }

        $secret = openssl_pkey_derive($public->openSslPublicKey(), $private->openSslPrivateKey());
        if ($secret === false) {
            throw new InvalidSignatureException('Decryption failed.');
        }

        return str_pad($secret, (int) OpenSslKey::coordinateSize((string) $private->curve()), "\0", STR_PAD_LEFT);
    }

    /**
     * @param array<string, mixed> $header
     */
    private static function ephemeralKey(array $header, Key $recipient): Key
    {
        if (!isset($header['epk']) || !is_array($header['epk'])) {
            throw new MalformedTokenException('The "epk" header is missing.');
        }

        try {
            $ephemeral = Key::fromJwk($header['epk']);
        } catch (InvalidKeyException) {
            throw new MalformedTokenException('The "epk" header is not a valid key.');
        }

        if ($ephemeral->isPrivate()) {
            throw new MalformedTokenException('The "epk" header must be a public key.');
        }
        if ($ephemeral->curve() !== $recipient->curve()) {
            throw new InvalidKeyException('The key is on a different curve from the "epk" header.');
        }

        return $ephemeral;
    }

    /**
     * @param array<string, mixed> $header
     */
    private static function partyInfo(array $header, string $name): string
    {
        if (!isset($header[$name])) {
            return '';
        }

        $value = is_string($header[$name]) ? Base64Url::decode($header[$name]) : null;

        return $value ?? throw new MalformedTokenException("The \"$name\" header is not base64url.");
    }

    private static function rsaOaepEncrypt(Key $key, string $cek): string
    {
        if (!openssl_public_encrypt($cek, $encrypted, $key->openSslPublicKey(), OPENSSL_PKCS1_OAEP_PADDING)) {
            throw new InvalidKeyException('RSA encryption failed.');
        }

        return $encrypted;
    }

    private static function rsaOaepDecrypt(Key $key, string $encryptedKey): ?string
    {
        return openssl_private_decrypt($encryptedKey, $cek, $key->openSslPrivateKey(), OPENSSL_PKCS1_OAEP_PADDING)
            ? $cek
            : null;
    }
}
