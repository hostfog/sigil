<?php

declare(strict_types=1);

namespace HostFog\Sigil\Exception;

final class InvalidSignatureException extends SigilException
{
    protected const ERROR_CODE = 'invalid_signature';
}
