# Sigil for PHP

JWT, JWS, JWE and JWK for PHP 8.1+, by HostFog Ltd. Only needs the `openssl`, `sodium`, `json` and
`hash` extensions. The behaviour is defined in [SPEC.md](../SPEC.md) and shared with the Go,
TypeScript and Python versions.

## Install

```sh
composer require hostfog/sigil
```

## Sign and verify

```php
use HostFog\Sigil\Key;
use HostFog\Sigil\Sigil;

$key = Key::fromPem(file_get_contents('private.pem'), ['kid' => 'main']);

$jwt = Sigil::sign(['sub' => 'user-42', 'exp' => time() + 3600], $key, ['alg' => 'ES256']);

$token = Sigil::verify($jwt, $key->publicKey(), [
    'algorithms' => ['ES256'],
    'issuer' => 'https://auth.example.com',
    'audience' => 'api',
    'leeway' => 30,
]);

$token->claims['sub']; // "user-42"
```

Every failure is a `HostFog\Sigil\Exception\SigilException`; `getErrorCode()` returns the stable
code from the spec (`expired`, `invalid_signature`, ...).

## Encrypt and decrypt

```php
$key = Key::generate('ECDH-ES+A256KW');

$jwe = Sigil::encrypt(['card' => '4242'], $key->publicKey(), ['enc' => 'A256GCM']);
$token = Sigil::decrypt($jwe, $key);
```

## JWKS

```php
use HostFog\Sigil\KeySet;

$keys = KeySet::fromJson(file_get_contents('https://auth.example.com/.well-known/jwks.json'));

// Picks the key named by the token's "kid" header.
$token = Sigil::verify($jwt, $keys, ['algorithms' => ['RS256']]);

echo $keys->toJson(); // public keys only
```

## Development

```sh
composer install
vendor/bin/phpunit
php bin/interop.php gen /tmp/php.json && php bin/interop.php check /tmp/php.json
```
