<?php

declare(strict_types=1);

namespace HostFog\Sigil\Tests;

use HostFog\Sigil\Exception\InvalidClaimException;
use HostFog\Sigil\Exception\SigilException;
use HostFog\Sigil\Exception\TokenExpiredException;
use HostFog\Sigil\Exception\TokenNotYetValidException;
use HostFog\Sigil\Key;
use HostFog\Sigil\Sigil;
use HostFog\Sigil\Token;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ClaimsTest extends TestCase
{
    private const NOW = 1000;

    /**
     * @return iterable<string, array{array<string, mixed>, array<string, mixed>}>
     */
    public static function acceptedTokens(): iterable
    {
        yield 'no claims' => [[], []];
        yield 'exp in the future' => [['exp' => 1001], []];
        yield 'exp within leeway' => [['exp' => 995], ['leeway' => 10]];
        yield 'nbf reached' => [['nbf' => 1000], []];
        yield 'nbf within leeway' => [['nbf' => 1005], ['leeway' => 10]];
        yield 'float times' => [['exp' => 1000.5, 'nbf' => 999.5, 'iat' => 999.5], []];
        yield 'iat within leeway' => [['iat' => 1005], ['leeway' => 10]];
        yield 'maxAge' => [['iat' => 900], ['maxAge' => 100]];
        yield 'maxAge with leeway' => [['iat' => 890], ['maxAge' => 100, 'leeway' => 10]];
        yield 'issuer' => [['iss' => 'a'], ['issuer' => 'a']];
        yield 'issuer list' => [['iss' => 'b'], ['issuer' => ['a', 'b']]];
        yield 'audience string' => [['aud' => 'x'], ['audience' => 'x']];
        yield 'audience array' => [['aud' => ['x', 'y']], ['audience' => 'y']];
        yield 'audience list' => [['aud' => 'y'], ['audience' => ['x', 'y']]];
        yield 'subject' => [['sub' => 's'], ['subject' => 's']];
        yield 'required' => [['foo' => null], ['required' => ['foo']]];
        yield 'typ case-insensitive' => [[], ['typ' => 'jwt']];
    }

    /**
     * @return iterable<string, array{array<string, mixed>, array<string, mixed>, string}>
     */
    public static function rejectedTokens(): iterable
    {
        yield 'expired' => [['exp' => 1000], [], 'expired'];
        yield 'expired beyond leeway' => [['exp' => 990], ['leeway' => 10], 'expired'];
        yield 'not yet valid' => [['nbf' => 1001], [], 'not_yet_valid'];
        yield 'nbf beyond leeway' => [['nbf' => 1011], ['leeway' => 10], 'not_yet_valid'];
        yield 'iat in the future' => [['iat' => 1001], [], 'iat'];
        yield 'exp not a number' => [['exp' => '2000'], [], 'exp'];
        yield 'nbf not a number' => [['nbf' => true], [], 'nbf'];
        yield 'iat not a number' => [['iat' => null], [], 'iat'];
        yield 'maxAge exceeded' => [['iat' => 899], ['maxAge' => 100], 'expired'];
        yield 'maxAge without iat' => [[], ['maxAge' => 100], 'iat'];
        yield 'wrong issuer' => [['iss' => 'c'], ['issuer' => ['a', 'b']], 'iss'];
        yield 'missing issuer' => [[], ['issuer' => 'a'], 'iss'];
        yield 'wrong audience' => [['aud' => ['x']], ['audience' => 'z'], 'aud'];
        yield 'missing audience' => [[], ['audience' => 'x'], 'aud'];
        yield 'wrong subject' => [['sub' => 't'], ['subject' => 's'], 'sub'];
        yield 'missing subject' => [[], ['subject' => 's'], 'sub'];
        yield 'missing required' => [['a' => 1], ['required' => ['a', 'b']], 'b'];
        yield 'wrong typ' => [[], ['typ' => 'at+jwt'], 'typ'];
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $options
     */
    #[DataProvider('acceptedTokens')]
    public function testAccepted(array $claims, array $options): void
    {
        self::assertSame($claims, $this->verify($claims, $options)->claims);
        self::assertSame($claims, $this->decrypt($claims, $options)->claims);
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $options
     * @param string $failure an error code, or the claim an invalid_claim error names
     */
    #[DataProvider('rejectedTokens')]
    public function testRejected(array $claims, array $options, string $failure): void
    {
        $expected = match ($failure) {
            'expired' => TokenExpiredException::class,
            'not_yet_valid' => TokenNotYetValidException::class,
            default => InvalidClaimException::class,
        };

        foreach ([$this->verify(...), $this->decrypt(...)] as $check) {
            try {
                $check($claims, $options);
                self::fail("Expected $expected.");
            } catch (SigilException $e) {
                self::assertInstanceOf($expected, $e);
                if ($e instanceof InvalidClaimException) {
                    self::assertSame('invalid_claim', $e->getErrorCode());
                    self::assertSame($failure, $e->claim);
                } else {
                    self::assertSame($failure, $e->getErrorCode());
                }
            }
        }
    }

    public function testDefaultsToCurrentTime(): void
    {
        $key = Fixtures::key('oct-hs256');

        $this->expectException(TokenExpiredException::class);
        Sigil::verify(Sigil::sign(['exp' => time() - 1], $key), $key);
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $options
     */
    private function verify(array $claims, array $options): Token
    {
        $key = Fixtures::key('oct-hs256');

        return Sigil::verify(Sigil::sign($claims, $key), $key, $options + ['now' => self::NOW]);
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $options
     */
    private function decrypt(array $claims, array $options): Token
    {
        $key = Key::generate('ECDH-ES');

        return Sigil::decrypt(Sigil::encrypt($claims, $key->publicKey()), $key, $options + ['now' => self::NOW]);
    }
}
