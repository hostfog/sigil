<?php

declare(strict_types=1);

namespace HostFog\Sigil\Crypto;

use HostFog\Sigil\Encoding\Base64Url;
use HostFog\Sigil\Encoding\Der;
use HostFog\Sigil\Exception\InvalidKeyException;
use OpenSSLAsymmetricKey;

/**
 * Converts between JWK members and OpenSSL keys.
 *
 * @internal
 */
final class OpenSslKey
{
    private const CURVES = [
        'P-256' => ['name' => 'prime256v1', 'oid' => '1.2.840.10045.3.1.7', 'size' => 32],
        'P-384' => ['name' => 'secp384r1', 'oid' => '1.3.132.0.34', 'size' => 48],
        'P-521' => ['name' => 'secp521r1', 'oid' => '1.3.132.0.35', 'size' => 66],
    ];

    private const RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
    private const EC_PUBLIC_KEY = '1.2.840.10045.2.1';

    // PHP's OpenSSL details for OKP keys differ between versions, so their fixed DER prefixes are matched instead.
    private const OKP_PUBLIC_PREFIXES = [
        'Ed25519' => '302a300506032b6570032100',
        'X25519' => '302a300506032b656e032100',
    ];
    private const OKP_PRIVATE_PREFIXES = [
        'Ed25519' => '302e020100300506032b657004220420',
        'X25519' => '302e020100300506032b656e04220420',
    ];

    public static function coordinateSize(string $curve): ?int
    {
        return self::CURVES[$curve]['size'] ?? null;
    }

    public static function curveName(string $curve): string
    {
        return self::CURVES[$curve]['name'];
    }

    /**
     * @param array<string, string> $params raw JWK members
     */
    public static function import(string $type, ?string $curve, array $params): OpenSSLAsymmetricKey
    {
        $private = isset($params['d']);
        $pem = $type === 'RSA' ? self::rsaPem($params, $private) : self::ecPem((string) $curve, $params, $private);

        $key = $private ? openssl_pkey_get_private($pem) : openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new InvalidKeyException("Invalid $type key.");
        }

        return $key;
    }

    /**
     * @return array<string, string> JWK
     */
    public static function readPem(string $pem): array
    {
        $okp = self::readOkp($pem);
        if ($okp !== null) {
            return $okp;
        }

        $private = str_contains($pem, 'PRIVATE KEY-----');
        $key = $private ? openssl_pkey_get_private($pem) : openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new InvalidKeyException('Unable to read the PEM key.');
        }

        return self::export($key);
    }

    /**
     * @return array<string, string> JWK
     */
    public static function export(OpenSSLAsymmetricKey $key): array
    {
        $details = openssl_pkey_get_details($key);

        return match ($details['type']) {
            OPENSSL_KEYTYPE_RSA => self::exportRsa($details['rsa']),
            OPENSSL_KEYTYPE_EC => self::exportEc($details['ec'] ?? []),
            default => throw new InvalidKeyException('Unsupported key type.'),
        };
    }

    /**
     * @param array<string, string> $rsa
     *
     * @return array<string, string>
     */
    private static function exportRsa(array $rsa): array
    {
        $members = ['n' => $rsa['n'], 'e' => $rsa['e']];
        if (isset($rsa['d'])) {
            $members += [
                'd' => $rsa['d'],
                'p' => $rsa['p'],
                'q' => $rsa['q'],
                'dp' => $rsa['dmp1'],
                'dq' => $rsa['dmq1'],
                'qi' => $rsa['iqmp'],
            ];
        }

        return ['kty' => 'RSA'] + array_map(Base64Url::encode(...), $members);
    }

    /**
     * @param array<string, string> $ec
     *
     * @return array<string, string>
     */
    private static function exportEc(array $ec): array
    {
        $openSslNames = array_map(static fn (array $curve): string => $curve['name'], self::CURVES);
        $curve = array_search($ec['curve_name'] ?? null, $openSslNames, true);
        if ($curve === false) {
            throw new InvalidKeyException('Unsupported elliptic curve.');
        }

        $size = self::CURVES[$curve]['size'];
        $jwk = ['kty' => 'EC', 'crv' => $curve];
        foreach (['x', 'y', 'd'] as $member) {
            if (isset($ec[$member])) {
                // OpenSSL drops leading zero bytes; JWK coordinates are fixed length.
                $jwk[$member] = Base64Url::encode(str_pad($ec[$member], $size, "\0", STR_PAD_LEFT));
            }
        }

        return $jwk;
    }

    /**
     * @return array<string, string>|null JWK, or null when the PEM is not an OKP key
     */
    private static function readOkp(string $pem): ?array
    {
        $der = self::unpem($pem);

        $curve = self::matchPrefix($der, self::OKP_PUBLIC_PREFIXES);
        if ($curve !== null) {
            return ['kty' => 'OKP', 'crv' => $curve, 'x' => Base64Url::encode(substr($der, -32))];
        }

        $curve = self::matchPrefix($der, self::OKP_PRIVATE_PREFIXES);
        if ($curve === null) {
            return null;
        }

        $d = substr($der, -32);
        $x = $curve === 'Ed25519'
            ? sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($d))
            : sodium_crypto_scalarmult_base($d);

        return ['kty' => 'OKP', 'crv' => $curve, 'x' => Base64Url::encode($x), 'd' => Base64Url::encode($d)];
    }

    /**
     * @param array<string, string> $prefixes hex DER prefix by curve, each followed by 32 key bytes
     */
    private static function matchPrefix(string $der, array $prefixes): ?string
    {
        foreach ($prefixes as $curve => $prefix) {
            $prefix = hex2bin($prefix);
            if (strlen($der) === strlen($prefix) + 32 && str_starts_with($der, $prefix)) {
                return $curve;
            }
        }

        return null;
    }

    /**
     * @param array<string, string> $params
     */
    private static function rsaPem(array $params, bool $private): string
    {
        if ($private) {
            $fields = array_map(
                static fn (string $name): string => Der::integer($params[$name]),
                ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'],
            );

            return self::pem('RSA PRIVATE KEY', Der::sequence(Der::integer("\0"), ...$fields));
        }

        return self::pem('PUBLIC KEY', self::subjectPublicKeyInfo(
            Der::oid(self::RSA_ENCRYPTION) . Der::null(),
            Der::sequence(Der::integer($params['n']), Der::integer($params['e'])),
        ));
    }

    /**
     * @param array<string, string> $params
     */
    private static function ecPem(string $curve, array $params, bool $private): string
    {
        $curveOid = Der::oid(self::CURVES[$curve]['oid']);
        $point = "\x04" . $params['x'] . $params['y'];

        if ($private) {
            return self::pem('EC PRIVATE KEY', Der::sequence(
                Der::integer("\x01"),
                Der::octetString($params['d']),
                Der::explicit(0, $curveOid),
                Der::explicit(1, Der::bitString($point)),
            ));
        }

        return self::pem('PUBLIC KEY', self::subjectPublicKeyInfo(Der::oid(self::EC_PUBLIC_KEY) . $curveOid, $point));
    }

    private static function subjectPublicKeyInfo(string $algorithm, string $publicKey): string
    {
        return Der::sequence(Der::sequence($algorithm), Der::bitString($publicKey));
    }

    private static function pem(string $label, string $der): string
    {
        return "-----BEGIN $label-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END $label-----\n";
    }

    private static function unpem(string $pem): string
    {
        return (string) base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $pem), true);
    }
}
