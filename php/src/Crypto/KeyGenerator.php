<?php

declare(strict_types=1);

namespace HostFog\Sigil\Crypto;

use HostFog\Sigil\Algorithm;
use HostFog\Sigil\Encoding\Base64Url;
use HostFog\Sigil\Exception\UnsupportedAlgorithmException;

/**
 * @internal
 */
final class KeyGenerator
{
    /**
     * @return array<string, string> JWK
     */
    public static function forAlgorithm(string $alg): array
    {
        return match ($alg) {
            Algorithm::HS256, Algorithm::DIR, Algorithm::A256KW => self::secret(32),
            Algorithm::HS384 => self::secret(48),
            Algorithm::HS512 => self::secret(64),
            Algorithm::A128KW => self::secret(16),
            Algorithm::A192KW => self::secret(24),
            Algorithm::RS256, Algorithm::RS384, Algorithm::RS512,
            Algorithm::PS256, Algorithm::PS384, Algorithm::PS512,
            Algorithm::RSA_OAEP, Algorithm::RSA_OAEP_256 => self::rsa(),
            Algorithm::ES256, Algorithm::ECDH_ES, Algorithm::ECDH_ES_A128KW,
            Algorithm::ECDH_ES_A192KW, Algorithm::ECDH_ES_A256KW => self::ec('P-256'),
            Algorithm::ES384 => self::ec('P-384'),
            Algorithm::ES512 => self::ec('P-521'),
            Algorithm::EDDSA => self::ed25519(),
            default => throw new UnsupportedAlgorithmException('Unsupported algorithm.'),
        };
    }

    /**
     * @return array<string, string>
     */
    public static function ec(string $curve): array
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => OpenSslKey::curveName($curve),
        ]);

        return OpenSslKey::export($key);
    }

    /**
     * @return array<string, string>
     */
    public static function x25519(): array
    {
        $private = random_bytes(SODIUM_CRYPTO_SCALARMULT_SCALARBYTES);

        return [
            'kty' => 'OKP',
            'crv' => 'X25519',
            'x' => Base64Url::encode(sodium_crypto_scalarmult_base($private)),
            'd' => Base64Url::encode($private),
        ];
    }

    /**
     * @return array<string, string>
     */
    private static function secret(int $length): array
    {
        return ['kty' => 'oct', 'k' => Base64Url::encode(random_bytes($length))];
    }

    /**
     * @return array<string, string>
     */
    private static function rsa(): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);

        return OpenSslKey::export($key);
    }

    /**
     * @return array<string, string>
     */
    private static function ed25519(): array
    {
        $pair = sodium_crypto_sign_keypair();

        return [
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'x' => Base64Url::encode(sodium_crypto_sign_publickey($pair)),
            'd' => Base64Url::encode(substr(sodium_crypto_sign_secretkey($pair), 0, SODIUM_CRYPTO_SIGN_SEEDBYTES)),
        ];
    }
}
