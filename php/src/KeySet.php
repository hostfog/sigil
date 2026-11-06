<?php

declare(strict_types=1);

namespace HostFog\Sigil;

use HostFog\Sigil\Encoding\Json;
use HostFog\Sigil\Exception\InvalidKeyException;

final class KeySet
{
    /** @var list<Key> */
    private array $keys = [];

    public function __construct(Key ...$keys)
    {
        foreach ($keys as $key) {
            $this->add($key);
        }
    }

    /**
     * Reads a JWKS. Entries with an unknown key type or curve are skipped.
     *
     * @param array{keys: list<array<string, mixed>>}|string $jwks
     */
    public static function fromJson(array|string $jwks): self
    {
        if (is_string($jwks)) {
            $jwks = Json::decodeObject($jwks) ?? throw new InvalidKeyException('The JWKS is not a JSON object.');
        }
        if (!isset($jwks['keys']) || !is_array($jwks['keys']) || !array_is_list($jwks['keys'])) {
            throw new InvalidKeyException('The JWKS has no "keys" list.');
        }

        $set = new self();
        foreach ($jwks['keys'] as $jwk) {
            if (is_array($jwk) && self::isSupported($jwk)) {
                $set->add(Key::fromJwk($jwk));
            }
        }

        return $set;
    }

    public function add(Key $key): void
    {
        $this->keys[] = $key;
    }

    public function get(string $kid): ?Key
    {
        foreach ($this->keys as $key) {
            if ($key->kid() === $kid) {
                return $key;
            }
        }

        return null;
    }

    /**
     * @return list<Key>
     */
    public function keys(): array
    {
        return $this->keys;
    }

    /**
     * Without $includePrivate only public keys are written and symmetric keys are left out.
     */
    public function toJson(bool $includePrivate = false): string
    {
        $jwks = [];
        foreach ($this->keys as $key) {
            if ($includePrivate || $key->type() !== 'oct') {
                $jwks[] = $key->toJwk($includePrivate);
            }
        }

        return Json::encode(['keys' => $jwks]);
    }

    /**
     * @param array<mixed> $jwk
     */
    private static function isSupported(array $jwk): bool
    {
        $type = $jwk['kty'] ?? null;
        if (!in_array($type, Key::TYPES, true)) {
            return false;
        }

        return !isset(Key::CURVES[$type]) || in_array($jwk['crv'] ?? null, Key::CURVES[$type], true);
    }
}
