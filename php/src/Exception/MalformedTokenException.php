<?php

declare(strict_types=1);

namespace HostFog\Sigil\Exception;

final class MalformedTokenException extends SigilException
{
    protected const ERROR_CODE = 'malformed';
}
