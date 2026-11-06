<?php

declare(strict_types=1);

namespace HostFog\Sigil\Exception;

final class InvalidClaimException extends SigilException
{
    protected const ERROR_CODE = 'invalid_claim';

    public function __construct(public readonly string $claim, string $message)
    {
        parent::__construct($message);
    }
}
