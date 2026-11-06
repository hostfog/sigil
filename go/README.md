# Sigil for Go

JWT, JWS, JWE and JWK for Go, using only the standard library. Behaviour is defined by
[SPEC.md](../SPEC.md) and shared with the TypeScript, PHP and Python versions.

```
go get github.com/hostfog/sigil/go
```

Requires Go 1.24.

## Sign and verify

```go
key := sigil.NewSecret(secret) // at least 32 bytes for HS256

token, err := sigil.Sign(map[string]any{
	"sub": "user-1",
	"iss": "auth.example.com",
	"exp": time.Now().Add(time.Hour).Unix(),
}, key)

tok, err := sigil.Verify(token, key,
	sigil.Issuer("auth.example.com"),
	sigil.Leeway(30*time.Second),
)
if errors.Is(err, sigil.ErrExpired) {
	// ...
}

var claims struct {
	Sub string `json:"sub"`
}
err = tok.Bind(&claims)
```

## Encrypt and decrypt

```go
key, err := sigil.GenerateKey(sigil.ECDHES)

token, err := sigil.Encrypt(claims, key.Public(),
	sigil.WithKeyAlgorithm(sigil.ECDHES),
	sigil.WithEncryption(sigil.A256GCM),
)

tok, err := sigil.Decrypt(token, key)
```

## JWKS

```go
keys, err := sigil.ParseJWKS(jwksJSON)

// The token's kid picks the key; without a kid every compatible key is tried.
tok, err := sigil.Verify(token, keys, sigil.Algorithms(sigil.RS256), sigil.Audience("api"))

public, err := keys.JSON(false) // safe to publish
```

PEM keys load with `sigil.ParsePEM` (PKCS#8, PKCS#1, SEC1, SPKI, X.509 certificates).

## Interop

```
cd go
go run ./cmd/sigil-interop gen out.json
go run ./cmd/sigil-interop check out.json
```
