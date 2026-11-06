<?php

declare(strict_types=1);

namespace HostFog\Sigil\Tests;

use HostFog\Sigil\Exception\InvalidKeyException;
use HostFog\Sigil\Exception\MalformedTokenException;
use HostFog\Sigil\Exception\SigilException;
use HostFog\Sigil\Exception\UnsupportedAlgorithmException;
use HostFog\Sigil\Key;
use HostFog\Sigil\Sigil;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TokenTest extends TestCase
{
    private const JWE_BODY = '..AAAAAAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA';

    public function testHeaderLayout(): void
    {
        $token = Sigil::sign(['a' => 1], Fixtures::key('ec-p256'), [
            'headers' => ['alg' => 'none', 'crit' => ['x'], 'zip' => 'DEF', 'cty' => 'demo', 'kid' => 'override'],
        ]);

        self::assertSame(
            ['alg' => 'ES256', 'typ' => 'JWT', 'kid' => 'override', 'cty' => 'demo'],
            Sigil::decode($token)->header,
        );
    }

    public function testJweHeaderLayout(): void
    {
        $token = Sigil::encrypt(['a' => 1], Fixtures::key('oct-a128kw'), [
            'alg' => 'A128KW',
            'kid' => 'mine',
            'typ' => 'secret+jwt',
            'headers' => ['enc' => 'A128GCM'],
        ]);
        $header = json_decode(base64_decode(explode('.', $token)[0]), true);

        self::assertSame(['alg' => 'A128KW', 'enc' => 'A256GCM', 'typ' => 'secret+jwt', 'kid' => 'mine'], $header);
    }

    public function testDefaultAlgorithms(): void
    {
        $expected = [
            'oct-hs256' => 'HS256',
            'rsa-2048' => 'RS256',
            'ec-p256' => 'ES256',
            'ec-p384' => 'ES384',
            'ec-p521' => 'ES512',
            'ed25519' => 'EdDSA',
        ];

        foreach ($expected as $kid => $alg) {
            self::assertSame($alg, Sigil::decode(Sigil::sign([], Fixtures::key($kid)))->header['alg']);
        }
    }

    public function testDecodeDoesNoChecks(): void
    {
        $token = Sigil::sign(['exp' => 1], Fixtures::key('oct-hs256'));

        self::assertSame(['exp' => 1], Sigil::decode(substr($token, 0, -2) . 'xx')->claims);
    }

    public function testDecodeRejectsJwe(): void
    {
        $this->expectException(MalformedTokenException::class);
        Sigil::decode(Sigil::encrypt([], Fixtures::key('dir-a256gcm'), ['alg' => 'dir']));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedTokens(): iterable
    {
        $header = self::b64('{"alg":"HS256"}');
        $payload = self::b64('{}');

        yield 'empty' => [''];
        yield 'two segments' => ["$header.$payload"];
        yield 'four segments' => ["$header.$payload.sig.x"];
        yield 'bad base64' => ["$header.$payload!.c2ln"];
        yield 'padded base64' => ["$header.$payload.c2lnbg=="];
        yield 'header not json' => [self::b64('nope') . ".$payload.c2ln"];
        yield 'header is a list' => [self::b64('["alg"]') . ".$payload.c2ln"];
        yield 'payload is a list' => ["$header." . self::b64('[]') . '.c2ln'];
        yield 'payload is a string' => ["$header." . self::b64('"x"') . '.c2ln'];
        yield 'missing alg' => [self::b64('{"typ":"JWT"}') . ".$payload.c2ln"];
        yield 'numeric kid' => [self::b64('{"alg":"HS256","kid":1}') . ".$payload.c2ln"];
    }

    #[DataProvider('malformedTokens')]
    public function testMalformed(string $token): void
    {
        $this->expectException(MalformedTokenException::class);
        Sigil::verify($token, Fixtures::key('oct-hs256'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function noneVariants(): iterable
    {
        foreach (['none', 'None', 'NONE', 'nOnE'] as $alg) {
            yield $alg => [$alg];
        }
    }

    #[DataProvider('noneVariants')]
    public function testNoneIsNeverAccepted(string $alg): void
    {
        $token = self::b64(json_encode(['alg' => $alg])) . '.' . self::b64('{"sub":"admin"}') . '.';

        $this->expectException(UnsupportedAlgorithmException::class);
        Sigil::verify($token, Fixtures::key('oct-hs256'), ['algorithms' => ['none', $alg, 'HS256']]);
    }

    #[DataProvider('noneVariants')]
    public function testNoneCannotSign(string $alg): void
    {
        $this->expectException(UnsupportedAlgorithmException::class);
        Sigil::sign([], Fixtures::key('oct-hs256'), ['alg' => $alg]);
    }

    public function testAlgorithmNotInAllowList(): void
    {
        $key = Fixtures::key('rsa-2048');

        $this->expectException(UnsupportedAlgorithmException::class);
        Sigil::verify(Sigil::sign([], $key, ['alg' => 'PS256']), $key, ['algorithms' => ['RS256']]);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function rejectedHeaders(): iterable
    {
        yield 'crit' => ['"crit":["exp"],"exp":1'];
        yield 'zip' => ['"zip":"DEF"'];
    }

    #[DataProvider('rejectedHeaders')]
    public function testCritAndZipAreRejected(string $extra): void
    {
        $key = Key::secret(str_repeat('s', 32));
        $input = self::b64('{"alg":"HS256",' . $extra . '}') . '.' . self::b64('{}');
        $jws = $input . '.' . self::b64(hash_hmac('sha256', $input, str_repeat('s', 32), true));
        $jwe = self::b64('{"alg":"dir","enc":"A256GCM",' . $extra . '}') . self::JWE_BODY;

        $this->assertCode('unsupported_alg', fn () => Sigil::verify($jws, $key));
        $this->assertCode('unsupported_alg', fn () => Sigil::decrypt($jwe, Fixtures::key('dir-a256gcm')));
    }

    public function testUnknownEncIsRejected(): void
    {
        $jwe = self::b64('{"alg":"dir","enc":"A512GCM"}') . self::JWE_BODY;

        $this->assertCode('unsupported_alg', fn () => Sigil::decrypt($jwe, Fixtures::key('dir-a256gcm')));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function mismatchedKeys(): iterable
    {
        yield 'HS with RSA key' => ['HS256', 'rsa-2048'];
        yield 'RS with oct key' => ['RS256', 'oct-hs256'];
        yield 'ES256 with P-384' => ['ES256', 'ec-p384'];
        yield 'ES512 with P-256' => ['ES512', 'ec-p256'];
        yield 'EdDSA with X25519' => ['EdDSA', 'x25519'];
        yield 'ES256 with Ed25519' => ['ES256', 'ed25519'];
        yield 'short HS384 key' => ['HS384', 'oct-hs256'];
        yield 'short HS512 key' => ['HS512', 'oct-hs384'];
        yield 'RSA-OAEP with EC key' => ['RSA-OAEP', 'ec-p256'];
        yield 'ECDH-ES with Ed25519' => ['ECDH-ES', 'ed25519'];
        yield 'A128KW with 24 byte key' => ['A128KW', 'oct-a192kw'];
        yield 'A256KW with 16 byte key' => ['A256KW', 'oct-a128kw'];
        yield 'dir with wrong length' => ['dir', 'dir-a128gcm'];
    }

    #[DataProvider('mismatchedKeys')]
    public function testKeyMustSuitAlgorithm(string $alg, string $kid): void
    {
        $key = Fixtures::key($kid);
        $sign = in_array($alg, ['HS256', 'HS384', 'HS512', 'RS256', 'ES256', 'ES512', 'EdDSA'], true);

        $this->assertCode('invalid_key', fn () => $sign
            ? Sigil::sign([], $key, ['alg' => $alg])
            : Sigil::encrypt([], $key, ['alg' => $alg]));
    }

    public function testShortHmacKeyIsRejectedOnVerify(): void
    {
        $short = Key::secret(str_repeat('s', 31));
        $token = self::b64('{"alg":"HS256"}') . '.' . self::b64('{}');
        $token .= '.' . self::b64(hash_hmac('sha256', $token, str_repeat('s', 31), true));

        $this->assertCode('invalid_key', fn () => Sigil::sign([], $short));
        $this->assertCode('invalid_key', fn () => Sigil::verify($token, $short));
    }

    public function testHmacWithRsaPublicKeyConfusion(): void
    {
        $public = Fixtures::key('rsa-2048')->publicKey();
        $pem = (string) file_get_contents(Fixtures::path('rsa-2048.pub.pem'));
        $input = self::b64('{"alg":"HS256"}') . '.' . self::b64('{"sub":"admin"}');
        $forged = $input . '.' . self::b64(hash_hmac('sha256', $input, $pem, true));

        $this->assertCode('invalid_key', fn () => Sigil::verify($forged, $public));
        $this->assertCode('invalid_key', fn () => Sigil::verify($forged, $public, ['algorithms' => ['HS256']]));
        $this->assertCode('invalid_key', fn () => Sigil::verify($forged, Key::fromPem($pem)));
    }

    public function testKeyAlgIsAlwaysEnforced(): void
    {
        $key = Key::fromJwk(Fixtures::jwk('rsa-2048'), ['alg' => 'RS256']);
        $token = Sigil::sign([], Fixtures::key('rsa-2048'), ['alg' => 'PS256']);

        $this->assertCode('invalid_key', fn () => Sigil::verify($token, $key, ['algorithms' => ['PS256']]));
        $this->assertCode('invalid_key', fn () => Sigil::sign([], $key, ['alg' => 'PS256']));
    }

    public function testPrivateKeyIsNeeded(): void
    {
        $ec = Fixtures::key('ec-p256')->publicKey();
        $rsa = Fixtures::key('rsa-2048');
        $jwe = Sigil::encrypt([], $rsa->publicKey(), ['alg' => 'RSA-OAEP']);

        $this->assertCode('invalid_key', fn () => Sigil::sign([], $ec));
        $this->assertCode('invalid_key', fn () => Sigil::decrypt($jwe, $rsa->publicKey()));
    }

    public function testEncryptNeedsAlgorithm(): void
    {
        $this->assertCode('unsupported_alg', fn () => Sigil::encrypt([], Fixtures::key('oct-a128kw')));
        $this->assertCode('unsupported_alg', fn () => Sigil::encrypt([], Key::generate('RS256')));
        $this->assertCode(
            'unsupported_alg',
            fn () => Sigil::encrypt([], Key::generate('A128KW'), ['enc' => 'A128CTR']),
        );
    }

    public function testEpkOnAnotherCurve(): void
    {
        $jwe = Sigil::encrypt([], Fixtures::key('ec-p384')->publicKey(), ['alg' => 'ECDH-ES']);

        $this->assertCode('invalid_key', fn () => Sigil::decrypt($jwe, Fixtures::key('ec-p256')));
    }

    public function testMissingOrInvalidEpk(): void
    {
        $key = Fixtures::key('ec-p256');
        $segments = explode('.', Sigil::encrypt([], $key->publicKey(), ['alg' => 'ECDH-ES']));
        $header = json_decode(base64_decode($segments[0]), true);

        foreach ([null, 'x', ['kty' => 'EC', 'crv' => 'P-256', 'x' => 'AA', 'y' => 'AA']] as $epk) {
            $header['epk'] = $epk;
            $segments[0] = self::b64(json_encode($header));
            $this->assertCode('malformed', fn () => Sigil::decrypt(implode('.', $segments), $key));
        }
    }

    public function testTamperedSignature(): void
    {
        foreach (['oct-hs256', 'rsa-2048', 'ec-p256', 'ed25519'] as $kid) {
            $key = Fixtures::key($kid);
            foreach (['HS256', 'RS256', 'PS256', 'ES256', 'EdDSA'] as $alg) {
                try {
                    $token = Sigil::sign(['a' => 1], $key, ['alg' => $alg]);
                } catch (InvalidKeyException) {
                    continue;
                }
                [$header, $payload, $signature] = explode('.', $token);

                $this->assertCode('invalid_signature', fn () => Sigil::verify(
                    "$header.$payload." . self::flipLastByte($signature),
                    $key,
                ));
                $this->assertCode('invalid_signature', fn () => Sigil::verify(
                    "$header." . self::b64('{"a":2}') . ".$signature",
                    $key,
                ));
            }
        }
    }

    public function testTruncatedEcdsaSignature(): void
    {
        $key = Fixtures::key('ec-p256');
        [$header, $payload, $signature] = explode('.', Sigil::sign([], $key));
        $truncated = self::b64(substr((string) base64_decode(strtr($signature, '-_', '+/')), 0, 63));

        $this->assertCode('invalid_signature', fn () => Sigil::verify("$header.$payload.$truncated", $key));
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function jweAlgorithms(): iterable
    {
        yield 'dir gcm' => ['dir', 'A256GCM', 'dir-a256gcm'];
        yield 'dir cbc' => ['dir', 'A128CBC-HS256', 'dir-a128cbc-hs256'];
        yield 'A128KW' => ['A128KW', 'A128GCM', 'oct-a128kw'];
        yield 'RSA-OAEP' => ['RSA-OAEP', 'A256GCM', 'rsa-2048'];
        yield 'RSA-OAEP-256' => ['RSA-OAEP-256', 'A256CBC-HS512', 'rsa-2048'];
        yield 'ECDH-ES' => ['ECDH-ES', 'A192GCM', 'x25519'];
        yield 'ECDH-ES+A256KW' => ['ECDH-ES+A256KW', 'A192CBC-HS384', 'ec-p521'];
    }

    #[DataProvider('jweAlgorithms')]
    public function testTamperedJwe(string $alg, string $enc, string $kid): void
    {
        $key = Fixtures::key($kid);
        $segments = explode('.', Sigil::encrypt(['a' => 1], $key, ['alg' => $alg, 'enc' => $enc]));

        foreach ([1, 2, 3, 4] as $index) {
            if ($segments[$index] === '') {
                continue;
            }
            $tampered = $segments;
            $tampered[$index] = self::flipLastByte($tampered[$index]);

            $this->assertCode('invalid_signature', fn () => Sigil::decrypt(implode('.', $tampered), $key));
        }

        $header = json_decode(base64_decode($segments[0]), true);
        $tampered = $segments;
        $tampered[0] = self::b64(json_encode(['cty' => 'x'] + $header));
        $this->assertCode('invalid_signature', fn () => Sigil::decrypt(implode('.', $tampered), $key));
    }

    public function testDirectJweWithEncryptedKeyIsMalformed(): void
    {
        $segments = explode('.', Sigil::encrypt([], Fixtures::key('dir-a256gcm'), ['alg' => 'dir']));
        $segments[1] = 'AAAA';

        $this->assertCode(
            'malformed',
            fn () => Sigil::decrypt(implode('.', $segments), Fixtures::key('dir-a256gcm')),
        );
    }

    public function testWrongKeyFailsDecryption(): void
    {
        $jwe = Sigil::encrypt([], Fixtures::key('x25519'), ['alg' => 'ECDH-ES']);
        $private = random_bytes(32);
        $other = Key::fromJwk([
            'kty' => 'OKP',
            'crv' => 'X25519',
            'x' => self::b64(sodium_crypto_scalarmult_base($private)),
            'd' => self::b64($private),
        ]);

        $this->assertCode('invalid_signature', fn () => Sigil::decrypt($jwe, $other));
    }

    private function assertCode(string $code, callable $operation): void
    {
        try {
            $operation();
        } catch (SigilException $e) {
            self::assertSame($code, $e->getErrorCode(), $e->getMessage());

            return;
        }

        self::fail("Expected a \"$code\" error.");
    }

    private static function b64(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function flipLastByte(string $segment): string
    {
        $bytes = base64_decode(strtr($segment, '-_', '+/'));
        $bytes[-1] = chr(ord($bytes[-1]) ^ 1);

        return self::b64($bytes);
    }
}
