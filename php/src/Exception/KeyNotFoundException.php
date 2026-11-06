<?php

declare(strict_types=1);

namespace HostFog\Sigil\Exception;

final class KeyNotFoundException extends SigilException
{
    protected const ERROR_CODE = 'key_not_found';
}
