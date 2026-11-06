<?php

declare(strict_types=1);

namespace HostFog\Sigil\Exception;

final class TokenExpiredException extends SigilException
{
    protected const ERROR_CODE = 'expired';
}
