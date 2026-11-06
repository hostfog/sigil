<?php

declare(strict_types=1);

namespace HostFog\Sigil\Tests;

use HostFog\Sigil\Exception\InvalidSignatureException;
use HostFog\Sigil\Exception\KeyNotFoundException;
use HostFog\Sigil\Key;
use HostFog\Sigil\KeySet;
use HostFog\Sigil\Sigil;
use PHPUnit\Framework\TestCase;

final class KeySetTest extends TestCase
{
    public function testFromJson(): void
    {
        $set = KeySet::fromJson((string) file_get_contents(Fixtures::path('keys.json')));

        self::assertCount(18, $set->keys());
        self::assertSame('P-521', $set->get('ec-p521')?->curve());
        self::assertNull($set->get('missing'));
    }

    public function testUnsupportedEntriesAreSkipped(): void
    {
        $set = KeySet::fromJson(['keys' => [
            ['kty' => 'XYZ', 'kid' => 'unknown'],
            ['kty' => 'EC', 'crv' => 'secp256k1', 'x' => 'AA', 'y' => 'AA', 'kid' => 'k1'],
            ['kty' => 'OKP', 'crv' => 'Ed448', 'x' => 'AA', 'kid' => 'ed448'],
            Fixtures::jwk('ed25519'),
        ]]);

        self::assertSame(['ed25519'], array_map(static fn (Key $key) => $key->kid(), $set->keys()));
    }

    public function testToJson(): void
    {
        $set = new KeySet(Fixtures::key('oct-hs256'), Fixtures::key('ec-p256'));

        self::assertEquals(
            ['keys' => [array_diff_key(Fixtures::jwk('ec-p256'), ['d' => true])]],
            json_decode($set->toJson(), true),
        );
        self::assertEqualsCanonicalizing(
            ['keys' => [Fixtures::jwk('oct-hs256'), Fixtures::jwk('ec-p256')]],
            json_decode($set->toJson(true), true),
        );
    }

    public function testSelectsKeyByKid(): void
    {
        $set = Fixtures::keys();

        foreach (['oct-hs512', 'rsa-2048', 'ec-p384', 'ed25519'] as $kid) {
            $token = Sigil::sign(['kid' => $kid], Fixtures::key($kid));
            self::assertSame($kid, Sigil::verify($token, $set)->claims['kid']);
        }

        $jwe = Sigil::encrypt([], Fixtures::key('x25519'), ['alg' => 'ECDH-ES+A128KW']);
        self::assertSame('x25519', Sigil::decrypt($jwe, $set)->header['kid']);
    }

    public function testUnknownKid(): void
    {
        $token = Sigil::sign([], Fixtures::key('oct-hs256'), ['kid' => 'nope']);

        $this->expectException(KeyNotFoundException::class);
        Sigil::verify($token, Fixtures::keys());
    }

    public function testWithoutKidEveryCompatibleKeyIsTried(): void
    {
        $first = Key::generate('ES256');
        $second = Key::generate('ES256');
        $set = new KeySet(Fixtures::key('rsa-2048'), $first->publicKey(), $second->publicKey());

        $token = Sigil::sign(['n' => 2], Key::fromJwk($second->toJwk(true)));
        self::assertSame(['n' => 2], Sigil::verify($token, $set)->claims);

        $jweSet = new KeySet(Key::generate('A128KW'), Fixtures::key('oct-a128kw'));
        $jwe = Sigil::encrypt(['n' => 3], Key::secret((string) base64_decode('zqAcjz9XumxaNuFNTYDYLQ==')), [
            'alg' => 'A128KW',
        ]);
        self::assertSame(['n' => 3], Sigil::decrypt($jwe, $jweSet)->claims);
    }

    public function testWithoutKidNoCompatibleKey(): void
    {
        $token = Sigil::sign([], Key::generate('EdDSA'));

        $this->expectException(KeyNotFoundException::class);
        Sigil::verify($token, new KeySet(Fixtures::key('rsa-2048'), Fixtures::key('ec-p256')));
    }

    public function testWithoutKidNoKeyVerifies(): void
    {
        $token = Sigil::sign([], Key::generate('ES256'));

        $this->expectException(InvalidSignatureException::class);
        Sigil::verify($token, new KeySet(Key::generate('ES256'), Key::generate('ES256')));
    }
}
