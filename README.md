# Sigil

JSON Web Tokens for Go, TypeScript, PHP and Python — one API, same behaviour everywhere.

- JWS: `HS256/384/512`, `RS256/384/512`, `PS256/384/512`, `ES256/384/512`, `EdDSA`
- JWE: `dir`, `A128KW/A192KW/A256KW`, `RSA-OAEP`, `RSA-OAEP-256`, `ECDH-ES` (+`A128KW/A192KW/A256KW`)
  with `A128GCM/A192GCM/A256GCM` and `A128CBC-HS256/A192CBC-HS384/A256CBC-HS512`
- JWK and JWKS, PEM keys, RFC 7638 thumbprints, key generation
- Claim validation: `exp`, `nbf`, `iat`, `iss`, `aud`, `sub`, max age, required claims, leeway
- Safe by default: no `none`, algorithm allow-lists, key/algorithm binding, minimum key sizes

Every implementation passes the same test vectors and verifies tokens issued by the others.

| Language | Package | Docs |
|---|---|---|
| Go | `github.com/hostfog/sigil/go` | [go/](go/README.md) |
| TypeScript / Node | `@hostfog/sigil` | [node/](node/README.md) |
| PHP | `hostfog/sigil` | [php/](php/README.md) |
| Python | `hostfog-sigil` | [python/](python/README.md) |

## Example

```ts
import { Key, sign, verify } from "@hostfog/sigil";

const key = Key.secret(process.env.JWT_SECRET!);
const token = sign({ sub: "42", exp: Math.floor(Date.now() / 1000) + 3600 }, key);
const { claims } = verify(token, key, { audience: "api" });
```

The same call in each language:

| | Go | TypeScript | PHP | Python |
|---|---|---|---|---|
| sign | `sigil.Sign(c, key)` | `sign(c, key)` | `Sigil::sign($c, $key)` | `sigil.sign(c, key)` |
| verify | `sigil.Verify(t, key, ...)` | `verify(t, key, opts)` | `Sigil::verify($t, $key, $opts)` | `sigil.verify(t, key, **opts)` |
| encrypt | `sigil.Encrypt(c, key, ...)` | `encrypt(c, key, opts)` | `Sigil::encrypt($c, $key, $opts)` | `sigil.encrypt(c, key, **opts)` |
| decrypt | `sigil.Decrypt(t, key, ...)` | `decrypt(t, key, opts)` | `Sigil::decrypt($t, $key, $opts)` | `sigil.decrypt(t, key, **opts)` |

Full behaviour is defined in [SPEC.md](SPEC.md).

## Development

```sh
cd go && go test ./...
cd node && npm ci && npm test
cd php && composer install && vendor/bin/phpunit
cd python && pip install -e '.[test]' && pytest
./interop/run.sh   # cross-language check
```

## License

MIT © HostFog Ltd
