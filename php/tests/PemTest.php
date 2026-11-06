<?php

declare(strict_types=1);

namespace HostFog\Sigil\Tests;

use HostFog\Sigil\Encoding\Der;
use HostFog\Sigil\Exception\InvalidKeyException;
use HostFog\Sigil\Key;
use HostFog\Sigil\Sigil;
use PHPUnit\Framework\TestCase;

final class PemTest extends TestCase
{
    public function testFixturePemMatchesJwk(): void
    {
        $private = Key::fromPem((string) file_get_contents(Fixtures::path('rsa-2048.pem')), ['kid' => 'rsa-2048']);
        $public = Key::fromPem((string) file_get_contents(Fixtures::path('rsa-2048.pub.pem')));

        self::assertEquals(Fixtures::jwk('rsa-2048'), $private->toJwk(true));
        self::assertFalse($public->isPrivate());
        self::assertSame(Fixtures::key('rsa-2048')->thumbprint(), $public->thumbprint());
    }

    public function testPkcs8AndSpki(): void
    {
        $curves = ['ES256' => 'prime256v1', 'ES384' => 'secp384r1', 'ES512' => 'secp521r1', 'RS256' => null];
        foreach ($curves as $alg => $curve) {
            $handle = $curve === null
                ? openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048])
                : openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve]);
            openssl_pkey_export($handle, $privatePem);
            $publicPem = openssl_pkey_get_details($handle)['key'];

            $this->assertSignsAndVerifies(Key::fromPem($privatePem), Key::fromPem($publicPem), $alg);
        }
    }

    public function testPkcs1(): void
    {
        $jwk = Fixtures::jwk('rsa-2048');
        $der = Der::sequence(Der::integer("\0"), ...array_map(
            static fn (string $name): string => Der::integer(self::b64decode($jwk[$name])),
            ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'],
        ));
        $publicDer = Der::sequence(Der::integer(self::b64decode($jwk['n'])), Der::integer(self::b64decode($jwk['e'])));

        $private = Key::fromPem(self::pem('RSA PRIVATE KEY', $der));
        $public = Key::fromPem(self::pem('RSA PUBLIC KEY', $publicDer));

        self::assertSame(array_diff_key($jwk, ['kid' => true]), $private->toJwk(true));
        $this->assertSignsAndVerifies($private, $public, 'PS256');
    }

    public function testSec1(): void
    {
        $jwk = Fixtures::jwk('ec-p521');
        $der = Der::sequence(
            Der::integer("\x01"),
            Der::octetString(self::b64decode($jwk['d'])),
            Der::explicit(0, Der::oid('1.3.132.0.35')),
            Der::explicit(1, Der::bitString("\x04" . self::b64decode($jwk['x']) . self::b64decode($jwk['y']))),
        );

        $key = Key::fromPem(self::pem('EC PRIVATE KEY', $der));

        self::assertSame(array_diff_key($jwk, ['kid' => true]), $key->toJwk(true));
    }

    public function testCertificate(): void
    {
        $handle = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $certificate = openssl_csr_sign(openssl_csr_new(['commonName' => 'sigil'], $handle), null, $handle, 1);
        openssl_x509_export($certificate, $certificatePem);
        openssl_pkey_export($handle, $privatePem);

        $public = Key::fromPem($certificatePem);

        self::assertFalse($public->isPrivate());
        $this->assertSignsAndVerifies(Key::fromPem($privatePem), $public, 'ES256');
    }

    public function testOkpKeys(): void
    {
        $ed25519 = Fixtures::jwk('ed25519');
        $x25519 = Fixtures::jwk('x25519');

        $private = Key::fromPem(self::okpPem('PRIVATE KEY', '302e020100300506032b657004220420', $ed25519['d']));
        $public = Key::fromPem(self::okpPem('PUBLIC KEY', '302a300506032b6570032100', $ed25519['x']));
        $exchange = Key::fromPem(self::okpPem('PRIVATE KEY', '302e020100300506032b656e04220420', $x25519['d']));

        self::assertSame(array_diff_key($ed25519, ['kid' => true]), $private->toJwk(true));
        self::assertSame(array_diff_key($ed25519, ['kid' => true, 'd' => true]), $public->toJwk());
        self::assertSame(array_diff_key($x25519, ['kid' => true]), $exchange->toJwk(true));
        $this->assertSignsAndVerifies($private, $public, 'EdDSA');
    }

    public function testGarbage(): void
    {
        $this->expectException(InvalidKeyException::class);
        Key::fromPem("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n");
    }

    private function assertSignsAndVerifies(Key $private, Key $public, string $alg): void
    {
        $token = Sigil::sign(['alg' => $alg], $private, ['alg' => $alg]);

        self::assertSame(['alg' => $alg], Sigil::verify($token, $public)->claims);
    }

    private static function pem(string $label, string $der): string
    {
        return "-----BEGIN $label-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END $label-----\n";
    }

    private static function okpPem(string $label, string $derPrefix, string $key): string
    {
        return self::pem($label, hex2bin($derPrefix) . self::b64decode($key));
    }

    private static function b64decode(string $data): string
    {
        return (string) base64_decode(strtr($data, '-_', '+/'));
    }
}
