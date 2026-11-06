<?php

declare(strict_types=1);

namespace HostFog\Sigil\Tests;

use HostFog\Sigil\Sigil;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class RoundTripTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string, ?string, string}>
     */
    public static function cases(): iterable
    {
        foreach (Fixtures::json('interop.json')['cases'] as $case) {
            $name = implode(' ', array_filter([$case['alg'], $case['enc'] ?? null, $case['key']]));
            yield $name => [$case['kind'], $case['alg'], $case['enc'] ?? null, $case['key']];
        }
    }

    #[DataProvider('cases')]
    public function testRoundTrip(string $kind, string $alg, ?string $enc, string $kid): void
    {
        $key = Fixtures::key($kid);
        $publicKey = $key->type() === 'oct' ? $key : $key->publicKey();
        $options = ['algorithms' => [$alg], 'now' => Fixtures::NOW, 'issuer' => 'sigil', 'audience' => 'all'];

        if ($kind === 'jws') {
            $token = Sigil::verify(Sigil::sign(Fixtures::claims(), $key, ['alg' => $alg]), $publicKey, $options);
        } else {
            $jwe = Sigil::encrypt(Fixtures::claims(), $publicKey, ['alg' => $alg, 'enc' => $enc]);
            $token = Sigil::decrypt($jwe, $key, $options);
            self::assertSame($enc, $token->header['enc']);
        }

        self::assertSame(Fixtures::claims(), $token->claims);
        self::assertSame($alg, $token->header['alg']);
        self::assertSame('JWT', $token->header['typ']);
        self::assertSame($kid, $token->header['kid']);
    }

    public function testEcdhUsesPartyInfoFromHeaders(): void
    {
        $key = Fixtures::key('ec-p256');
        $jwe = Sigil::encrypt(['a' => 1], $key->publicKey(), [
            'alg' => 'ECDH-ES',
            'headers' => ['apu' => 'QWxpY2U', 'apv' => 'Qm9i'],
        ]);

        self::assertSame(['a' => 1], Sigil::decrypt($jwe, $key)->claims);
    }

    public function testEmptyClaimsEncodeAsObject(): void
    {
        $token = Sigil::sign([], Fixtures::key('oct-hs256'));

        self::assertSame('{}', base64_decode(explode('.', $token)[1]));
        self::assertSame([], Sigil::verify($token, Fixtures::key('oct-hs256'))->claims);
    }

    public function testNumbersRoundTrip(): void
    {
        $claims = ['int' => 7, 'float' => 1.5, 'big' => 9007199254740993, 'list' => [1, 2.25]];
        $key = Fixtures::key('oct-hs256');

        self::assertSame($claims, Sigil::verify(Sigil::sign($claims, $key), $key)->claims);
    }
}
