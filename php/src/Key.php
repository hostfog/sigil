<?php

declare(strict_types=1);

namespace HostFog\Sigil;

use HostFog\Sigil\Crypto\KeyGenerator;
use HostFog\Sigil\Crypto\OpenSslKey;
use HostFog\Sigil\Crypto\Rsa;
use HostFog\Sigil\Encoding\Base64Url;
use HostFog\Sigil\Encoding\Json;
use HostFog\Sigil\Exception\InvalidKeyException;
use OpenSSLAsymmetricKey;

final class Key
{
    public const TYPES = ['oct', 'RSA', 'EC', 'OKP'];
    public const CURVES = [
        'EC' => ['P-256', 'P-384', 'P-521'],
        'OKP' => ['Ed25519', 'X25519'],
    ];

    private const PUBLIC_MEMBERS = [
        'oct' => ['k'],
        'RSA' => ['n', 'e'],
        'EC' => ['x', 'y'],
        'OKP' => ['x'],
    ];

    private const PRIVATE_MEMBERS = [
        'oct' => [],
        'RSA' => ['d', 'p', 'q', 'dp', 'dq', 'qi'],
        'EC' => ['d'],
        'OKP' => ['d'],
    ];

    private const OKP_KEY_SIZE = 32;
    private const MIN_RSA_BITS = 2048;

    private readonly ?OpenSSLAsymmetricKey $openSslPublicKey;
    private readonly ?OpenSSLAsymmetricKey $openSslPrivateKey;

    /**
     * @param array<string, string> $members raw (decoded) JWK key members
     */
    private function __construct(
        private readonly string $type,
        private readonly array $members,
        private readonly ?string $curve,
        private readonly ?string $kid,
        private readonly ?string $alg,
    ) {
        $this->validate();
        // PHP's OpenSSL functions will not take a private key where a public one is expected.
        $openSsl = in_array($type, ['RSA', 'EC'], true);
        $this->openSslPublicKey = $openSsl ? OpenSslKey::import($type, $curve, $this->publicMembers()) : null;
        $this->openSslPrivateKey = $openSsl && isset($members['d'])
            ? OpenSslKey::import($type, $curve, $members)
            : null;
    }

    /**
     * @param array<string, mixed>|string $jwk
     * @param array{kid?: string, alg?: string} $options
     */
    public static function fromJwk(array|string $jwk, array $options = []): self
    {
        if (is_string($jwk)) {
            $jwk = Json::decodeObject($jwk) ?? throw new InvalidKeyException('The JWK is not a JSON object.');
        }

        $type = $jwk['kty'] ?? null;
        if (!in_array($type, self::TYPES, true)) {
            throw new InvalidKeyException('Unsupported key type.');
        }

        $members = [];
        foreach ([...self::PUBLIC_MEMBERS[$type], ...self::PRIVATE_MEMBERS[$type]] as $name) {
            if (!isset($jwk[$name])) {
                continue;
            }
            $value = is_string($jwk[$name]) ? Base64Url::decode($jwk[$name]) : null;
            $members[$name] = $value ?? throw new InvalidKeyException("The JWK member \"$name\" is not base64url.");
        }

        return new self(
            $type,
            $members,
            in_array($type, ['EC', 'OKP'], true) ? self::optionalString($jwk, 'crv') : null,
            $options['kid'] ?? self::optionalString($jwk, 'kid'),
            $options['alg'] ?? self::optionalString($jwk, 'alg'),
        );
    }

    /**
     * Loads a PKCS#8, PKCS#1, SEC1 or SPKI key, or the public key of an X.509 certificate.
     *
     * @param array{kid?: string, alg?: string} $options
     */
    public static function fromPem(string $pem, array $options = []): self
    {
        return self::fromJwk(OpenSslKey::readPem($pem), $options);
    }

    /**
     * @param array{kid?: string, alg?: string} $options
     */
    public static function secret(string $bytes, array $options = []): self
    {
        return new self('oct', ['k' => $bytes], null, $options['kid'] ?? null, $options['alg'] ?? null);
    }

    /**
     * Creates a fresh key for the given JWS or JWE algorithm. The key is bound to that algorithm.
     *
     * @param array{kid?: string} $options
     */
    public static function generate(string $alg, array $options = []): self
    {
        return self::fromJwk(KeyGenerator::forAlgorithm($alg), ['alg' => $alg] + $options);
    }

    public function type(): string
    {
        return $this->type;
    }

    public function kid(): ?string
    {
        return $this->kid;
    }

    public function alg(): ?string
    {
        return $this->alg;
    }

    public function curve(): ?string
    {
        return $this->curve;
    }

    public function isPrivate(): bool
    {
        return $this->type === 'oct' || isset($this->members['d']);
    }

    public function publicKey(): self
    {
        if ($this->type === 'oct') {
            throw new InvalidKeyException('Symmetric keys have no public part.');
        }
        if (!$this->isPrivate()) {
            return $this;
        }

        return new self($this->type, $this->publicMembers(), $this->curve, $this->kid, $this->alg);
    }

    /**
     * @return array<string, string>
     */
    public function toJwk(bool $includePrivate = false): array
    {
        if ($this->type === 'oct' && !$includePrivate) {
            throw new InvalidKeyException('Symmetric keys have no public part.');
        }

        $jwk = ['kty' => $this->type];
        if ($this->curve !== null) {
            $jwk['crv'] = $this->curve;
        }

        $names = self::PUBLIC_MEMBERS[$this->type];
        if ($includePrivate) {
            $names = [...$names, ...self::PRIVATE_MEMBERS[$this->type]];
        }
        foreach ($names as $name) {
            if (isset($this->members[$name])) {
                $jwk[$name] = Base64Url::encode($this->members[$name]);
            }
        }

        if ($this->kid !== null) {
            $jwk['kid'] = $this->kid;
        }
        if ($this->alg !== null) {
            $jwk['alg'] = $this->alg;
        }

        return $jwk;
    }

    /**
     * RFC 7638 JWK thumbprint (SHA-256, base64url).
     */
    public function thumbprint(): string
    {
        $required = ['kty' => $this->type];
        if ($this->curve !== null) {
            $required['crv'] = $this->curve;
        }
        foreach (self::PUBLIC_MEMBERS[$this->type] as $name) {
            $required[$name] = Base64Url::encode($this->members[$name]);
        }
        ksort($required, SORT_STRING);

        return Base64Url::encode(hash('sha256', Json::encode($required), true));
    }

    /**
     * @internal raw key material by JWK member name
     */
    public function material(string $name): ?string
    {
        return $this->members[$name] ?? null;
    }

    /**
     * @internal
     */
    public function openSslPublicKey(): OpenSSLAsymmetricKey
    {
        return $this->openSslPublicKey ?? throw new InvalidKeyException('Not an RSA or EC key.');
    }

    /**
     * @internal
     */
    public function openSslPrivateKey(): OpenSSLAsymmetricKey
    {
        return $this->openSslPrivateKey ?? throw new InvalidKeyException('Not an RSA or EC private key.');
    }

    /**
     * @return array<string, string>
     */
    private function publicMembers(): array
    {
        return array_intersect_key($this->members, array_flip(self::PUBLIC_MEMBERS[$this->type]));
    }

    private function validate(): void
    {
        foreach (self::PUBLIC_MEMBERS[$this->type] as $name) {
            if (($this->members[$name] ?? '') === '') {
                throw new InvalidKeyException("The key is missing the \"$name\" member.");
            }
        }

        $private = array_intersect_key($this->members, array_flip(self::PRIVATE_MEMBERS[$this->type]));
        if ($private !== [] && count($private) !== count(self::PRIVATE_MEMBERS[$this->type])) {
            throw new InvalidKeyException('The private key is incomplete.');
        }

        if ($this->type === 'RSA') {
            $this->validateRsa();
        } elseif ($this->type !== 'oct') {
            $this->validateCurve();
        }
    }

    private function validateRsa(): void
    {
        if (Rsa::bitLength($this->members['n']) < self::MIN_RSA_BITS) {
            throw new InvalidKeyException('RSA keys must be at least 2048 bits.');
        }
    }

    private function validateCurve(): void
    {
        $size = match ($this->type) {
            'EC' => OpenSslKey::coordinateSize((string) $this->curve),
            'OKP' => in_array($this->curve, self::CURVES['OKP'], true) ? self::OKP_KEY_SIZE : null,
        };
        if ($size === null) {
            throw new InvalidKeyException("Unsupported curve for $this->type keys.");
        }

        foreach ($this->members as $value) {
            if (strlen($value) !== $size) {
                throw new InvalidKeyException('Key coordinates have the wrong length for the curve.');
            }
        }
    }

    /**
     * @param array<string, mixed> $jwk
     */
    private static function optionalString(array $jwk, string $name): ?string
    {
        $value = $jwk[$name] ?? null;
        if ($value !== null && !is_string($value)) {
            throw new InvalidKeyException("The JWK member \"$name\" must be a string.");
        }

        return $value;
    }
}
