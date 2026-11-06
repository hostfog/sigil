<?php

declare(strict_types=1);

namespace HostFog\Sigil\Exception;

use RuntimeException;

abstract class SigilException extends RuntimeException
{
    protected const ERROR_CODE = '';

    /**
     * The stable error code shared by every Sigil implementation, e.g. "expired".
     */
    public function getErrorCode(): string
    {
        return static::ERROR_CODE;
    }
}
