<?php

declare(strict_types=1);

namespace HostFog\Sigil\Tests;

use HostFog\Sigil\Key;
use HostFog\Sigil\Sigil;
use PHPUnit\Framework\TestCase;

final class VectorsTest extends TestCase
{
    public function testRfc7515AppendixA1(): void
    {
        $vector = Fixtures::json('vectors.json')['rfc7515_a1'];

        $token = Sigil::verify($vector['token'], Key::fromJwk($vector['key']), ['now' => $vector['now']]);

        self::assertSame($vector['claims'], $token->claims);
        self::assertSame(['typ' => 'JWT', 'alg' => 'HS256'], $token->header);
    }

    public function testRfc7638Thumbprint(): void
    {
        $vector = Fixtures::json('vectors.json')['rfc7638_thumbprint'];

        self::assertSame($vector['thumbprint'], Key::fromJwk($vector['key'])->thumbprint());
    }
}
