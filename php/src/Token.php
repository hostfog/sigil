<?php

declare(strict_types=1);

namespace HostFog\Sigil;

final class Token
{
    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public readonly array $header,
        public readonly array $claims,
    ) {
    }
}
