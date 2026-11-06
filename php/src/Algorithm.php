<?php

declare(strict_types=1);

namespace HostFog\Sigil;

final class Algorithm
{
    public const HS256 = 'HS256';
    public const HS384 = 'HS384';
    public const HS512 = 'HS512';
    public const RS256 = 'RS256';
    public const RS384 = 'RS384';
    public const RS512 = 'RS512';
    public const PS256 = 'PS256';
    public const PS384 = 'PS384';
    public const PS512 = 'PS512';
    public const ES256 = 'ES256';
    public const ES384 = 'ES384';
    public const ES512 = 'ES512';
    public const EDDSA = 'EdDSA';

    public const DIR = 'dir';
    public const A128KW = 'A128KW';
    public const A192KW = 'A192KW';
    public const A256KW = 'A256KW';
    public const RSA_OAEP = 'RSA-OAEP';
    public const RSA_OAEP_256 = 'RSA-OAEP-256';
    public const ECDH_ES = 'ECDH-ES';
    public const ECDH_ES_A128KW = 'ECDH-ES+A128KW';
    public const ECDH_ES_A192KW = 'ECDH-ES+A192KW';
    public const ECDH_ES_A256KW = 'ECDH-ES+A256KW';

    public const A128GCM = 'A128GCM';
    public const A192GCM = 'A192GCM';
    public const A256GCM = 'A256GCM';
    public const A128CBC_HS256 = 'A128CBC-HS256';
    public const A192CBC_HS384 = 'A192CBC-HS384';
    public const A256CBC_HS512 = 'A256CBC-HS512';

    public const SIGNATURE = [
        self::HS256, self::HS384, self::HS512,
        self::RS256, self::RS384, self::RS512,
        self::PS256, self::PS384, self::PS512,
        self::ES256, self::ES384, self::ES512,
        self::EDDSA,
    ];

    public const KEY_MANAGEMENT = [
        self::DIR,
        self::A128KW, self::A192KW, self::A256KW,
        self::RSA_OAEP, self::RSA_OAEP_256,
        self::ECDH_ES, self::ECDH_ES_A128KW, self::ECDH_ES_A192KW, self::ECDH_ES_A256KW,
    ];

    public const CONTENT_ENCRYPTION = [
        self::A128GCM, self::A192GCM, self::A256GCM,
        self::A128CBC_HS256, self::A192CBC_HS384, self::A256CBC_HS512,
    ];

    private function __construct()
    {
    }
}
