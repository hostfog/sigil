<?php

declare(strict_types=1);

namespace HostFog\Sigil\Exception;

final class InvalidKeyException extends SigilException
{
    protected const ERROR_CODE = 'invalid_key';
}
