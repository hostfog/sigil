<?php

declare(strict_types=1);

namespace HostFog\Sigil\Exception;

final class TokenNotYetValidException extends SigilException
{
    protected const ERROR_CODE = 'not_yet_valid';
}
