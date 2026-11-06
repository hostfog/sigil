<?php

declare(strict_types=1);

namespace HostFog\Sigil\Tests;

use HostFog\Sigil\Algorithm;
use HostFog\Sigil\Exception\InvalidKeyException;
use HostFog\Sigil\Exception\UnsupportedAlgorithmException;
use HostFog\Sigil\Key;
use HostFog\Sigil\Sigil;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class KeyTest extends TestCase
{
    /**
     * @return iterable<string, array{string}>
     */
    public static function algorithms(): iterable
    {
        foreach ([...Algorithm::SIGNATURE, ...Algorithm::KEY_MANAGEMENT] as $alg) {
            yield $alg => [$alg];
        }
    }

    #[DataProvider('algorithms')]
    public function testGeneratedKeysAreBoundAndUsable(string $alg): void
    {
        $key = Key::generate($alg, ['kid' => 'k1']);

        self::assertSame($alg, $key->alg());
        self::assertSame('k1', $key->kid());
        self::assertTrue($key->isPrivate());

        $recipient = $key->type() === 'oct' ? $key : $key->publicKey();
        $token = in_array($alg, Algorithm::SIGNATURE, true)
            ? Sigil::verify(Sigil::sign(['a' => 1], $key), $recipient)
            : Sigil::decrypt(Sigil::encrypt(['a' => 1], $recipient), $key);

        self::assertSame(['a' => 1], $token->claims);
    }

    public function testGenerateSizes(): void
    {
        self::assertSame(32, strlen(base64_decode(strtr(Key::generate('dir')->toJwk(true)['k'], '-_', '+/'))));
        self::assertSame('P-521', Key::generate('ES512')->curve());
        self::assertSame('Ed25519', Key::generate('EdDSA')->curve());

        $this->expectException(UnsupportedAlgorithmException::class);
        Key::generate('none');
    }

    public function testProperties(): void
    {
        $ec = Fixtures::key('ec-p384');
        self::assertSame('EC', $ec->type());
        self::assertSame('P-384', $ec->curve());
        self::assertSame('ec-p384', $ec->kid());
        self::assertNull($ec->alg());
        self::assertTrue($ec->isPrivate());
        self::assertFalse($ec->publicKey()->isPrivate());

        $rsa = Fixtures::key('rsa-2048');
        self::assertSame('RSA', $rsa->type());
        self::assertNull($rsa->curve());
        self::assertSame($rsa->thumbprint(), $rsa->publicKey()->thumbprint());
    }

    public function testJwkExport(): void
    {
        foreach (Fixtures::json('keys.json')['keys'] as $jwk) {
            $key = Key::fromJwk(json_encode($jwk, JSON_THROW_ON_ERROR));
            self::assertEqualsCanonicalizing($jwk, $key->toJwk(true));

            if ($jwk['kty'] !== 'oct') {
                $public = $key->toJwk();
                self::assertArrayNotHasKey('d', $public);
                self::assertSame($public, $key->publicKey()->toJwk(true));
            }
        }
    }

    public function testConstructorOptionsOverrideJwk(): void
    {
        $key = Key::fromJwk(Fixtures::key('ed25519')->toJwk(true), ['kid' => 'other', 'alg' => 'EdDSA']);

        self::assertSame('other', $key->kid());
        self::assertSame('EdDSA', $key->alg());
    }

    public function testSymmetricKeyHasNoPublicForm(): void
    {
        $key = Key::secret(str_repeat('k', 32));
        self::assertSame(['kty' => 'oct', 'k' => 'a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s'], $key->toJwk(true));

        $this->expectException(InvalidKeyException::class);
        $key->toJwk();
    }

    public function testSymmetricKeyHasNoPublicKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        Key::secret(str_repeat('k', 32))->publicKey();
    }

    /**
     * @return iterable<string, array{array<string, mixed>|string}>
     */
    public static function invalidJwks(): iterable
    {
        $ec = Fixtures::jwk('ec-p256');

        yield 'not json' => ['{'];
        yield 'json list' => ['[]'];
        yield 'unknown kty' => [['kty' => 'XYZ']];
        yield 'missing k' => [['kty' => 'oct']];
        yield 'empty k' => [['kty' => 'oct', 'k' => '']];
        yield 'padded base64' => [['kty' => 'oct', 'k' => 'YWJj=']];
        yield 'standard base64' => [['kty' => 'oct', 'k' => 'a+b/']];
        yield 'non-string member' => [['kty' => 'oct', 'k' => 5]];
        yield 'non-string kid' => [['kty' => 'oct', 'k' => 'YWJj', 'kid' => 1]];
        yield 'unknown curve' => [['crv' => 'P-192'] + $ec];
        yield 'short coordinate' => [['x' => 'AAAA'] + $ec];
        yield 'point not on curve' => [['y' => $ec['x']] + $ec];
        yield 'incomplete rsa private key' => [array_diff_key(Fixtures::jwk('rsa-2048'), ['qi' => 1])];
        yield 'okp wrong size' => [['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => 'AAAA']];
    }

    /**
     * @param array<string, mixed>|string $jwk
     */
    #[DataProvider('invalidJwks')]
    public function testInvalidJwk(array|string $jwk): void
    {
        $this->expectException(InvalidKeyException::class);
        Key::fromJwk($jwk);
    }

    public function testRsaUnder2048BitsIsRejected(): void
    {
        $small = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 1024]);
        openssl_pkey_export($small, $pem);

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('2048');
        Key::fromPem($pem);
    }
}
