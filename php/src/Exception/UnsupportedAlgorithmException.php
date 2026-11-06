<?php

declare(strict_types=1);

namespace HostFog\Sigil\Exception;

final class UnsupportedAlgorithmException extends SigilException
{
    protected const ERROR_CODE = 'unsupported_alg';
}
