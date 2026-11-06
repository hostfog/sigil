package sigil

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"slices"
)

// Key is a single signing or encryption key: a symmetric secret, or an
// RSA, EC (P-256, P-384, P-521) or OKP (Ed25519, X25519) key pair or public key.
type Key struct {
	kty    string
	kid    string
	alg    string
	crv    string
	secret []byte
	pub    crypto.PublicKey
	priv   crypto.PrivateKey
}

// KeyOption sets optional key properties when constructing a Key.
type KeyOption func(*Key)

// KeyID sets the key ID.
func KeyID(kid string) KeyOption {
	return func(k *Key) { k.kid = kid }
}

// KeyAlgorithm binds the key to a single algorithm.
func KeyAlgorithm(alg string) KeyOption {
	return func(k *Key) { k.alg = alg }
}

type ecCurve struct {
	ec   elliptic.Curve
	dh   ecdh.Curve
	size int
}

var ecCurves = map[string]ecCurve{
	"P-256": {elliptic.P256(), ecdh.P256(), 32},
	"P-384": {elliptic.P384(), ecdh.P384(), 48},
	"P-521": {elliptic.P521(), ecdh.P521(), 66},
}

// NewSecret returns a symmetric key holding a copy of secret.
func NewSecret(secret []byte, opts ...KeyOption) *Key {
	k := &Key{kty: "oct", secret: slices.Clone(secret)}
	k.apply(opts)
	return k
}

// GenerateKey creates a fresh key suited to a JWS or JWE key management
// algorithm and binds it to alg. A "dir" key is 32 bytes, for A256GCM or A128CBC-HS256.
func GenerateKey(alg string, opts ...KeyOption) (*Key, error) {
	var k *Key
	var err error
	switch alg {
	case HS256, HS384, HS512:
		k = NewSecret(randomBytes(hashes[alg].Size()))
	case A128KW, A192KW, A256KW:
		k = NewSecret(randomBytes(wrapSizes[alg]))
	case Dir:
		k = NewSecret(randomBytes(32))
	case RS256, RS384, RS512, PS256, PS384, PS512, RSAOAEP, RSAOAEP256:
		var priv *rsa.PrivateKey
		if priv, err = rsa.GenerateKey(rand.Reader, 2048); err == nil {
			k, err = fromCrypto(priv)
		}
	case ES256, ES384, ES512:
		k, err = generateCurve(ecdsaCurves[alg])
	case EdDSA:
		k, err = generateCurve("Ed25519")
	case ECDHES, ECDHESA128KW, ECDHESA192KW, ECDHESA256KW:
		k, err = generateCurve("P-256")
	default:
		return nil, fail(ErrUnsupportedAlg, "cannot generate a key for "+alg)
	}
	if err != nil {
		return nil, err
	}
	k.alg = alg
	k.apply(opts)
	return k, nil
}

func generateCurve(crv string) (*Key, error) {
	var priv any
	var err error
	switch crv {
	case "Ed25519":
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case "X25519":
		priv, err = ecdh.X25519().GenerateKey(rand.Reader)
	default:
		priv, err = ecdsa.GenerateKey(ecCurves[crv].ec, rand.Reader)
	}
	if err != nil {
		return nil, err
	}
	return fromCrypto(priv)
}

func fromCrypto(key any) (*Key, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &Key{kty: "RSA", pub: &k.PublicKey, priv: k}, nil
	case *rsa.PublicKey:
		return &Key{kty: "RSA", pub: k}, nil
	case *ecdsa.PrivateKey:
		if _, ok := ecCurves[k.Curve.Params().Name]; ok {
			return &Key{kty: "EC", crv: k.Curve.Params().Name, pub: &k.PublicKey, priv: k}, nil
		}
	case *ecdsa.PublicKey:
		if _, ok := ecCurves[k.Curve.Params().Name]; ok {
			return &Key{kty: "EC", crv: k.Curve.Params().Name, pub: k}, nil
		}
	case ed25519.PrivateKey:
		return &Key{kty: "OKP", crv: "Ed25519", pub: k.Public(), priv: k}, nil
	case ed25519.PublicKey:
		return &Key{kty: "OKP", crv: "Ed25519", pub: k}, nil
	case *ecdh.PrivateKey:
		if k.Curve() == ecdh.X25519() {
			return &Key{kty: "OKP", crv: "X25519", pub: k.PublicKey(), priv: k}, nil
		}
	case *ecdh.PublicKey:
		if k.Curve() == ecdh.X25519() {
			return &Key{kty: "OKP", crv: "X25519", pub: k}, nil
		}
	}
	return nil, fail(ErrInvalidKey, "unsupported key type")
}

func (k *Key) apply(opts []KeyOption) {
	for _, opt := range opts {
		opt(k)
	}
}

// Type returns the JWK key type: "oct", "RSA", "EC" or "OKP".
func (k *Key) Type() string { return k.kty }

// ID returns the key ID, if any.
func (k *Key) ID() string { return k.kid }

// Algorithm returns the algorithm the key is bound to, if any.
func (k *Key) Algorithm() string { return k.alg }

// Curve returns the curve name for EC and OKP keys.
func (k *Key) Curve() string { return k.crv }

// IsPrivate reports whether the key can sign or decrypt.
func (k *Key) IsPrivate() bool { return k.secret != nil || k.priv != nil }

// Public returns the public half of the key. It returns nil for symmetric keys.
func (k *Key) Public() *Key {
	if k.kty == "oct" {
		return nil
	}
	return &Key{kty: k.kty, kid: k.kid, alg: k.alg, crv: k.crv, pub: k.pub}
}

func (k *Key) defaultAlg() string {
	if k.alg != "" {
		return k.alg
	}
	switch k.kty {
	case "oct":
		return HS256
	case "RSA":
		return RS256
	}
	switch k.crv {
	case "P-256":
		return ES256
	case "P-384":
		return ES384
	case "P-521":
		return ES512
	case "Ed25519":
		return EdDSA
	}
	return ""
}

// fits reports whether alg can be used with the key's type and curve.
func (k *Key) fits(alg string) bool {
	switch alg {
	case HS256, HS384, HS512, Dir, A128KW, A192KW, A256KW:
		return k.kty == "oct"
	case RS256, RS384, RS512, PS256, PS384, PS512, RSAOAEP, RSAOAEP256:
		return k.kty == "RSA"
	case ES256, ES384, ES512:
		return k.kty == "EC" && k.crv == ecdsaCurves[alg]
	case EdDSA:
		return k.crv == "Ed25519"
	case ECDHES, ECDHESA128KW, ECDHESA192KW, ECDHESA256KW:
		return k.kty == "EC" || k.crv == "X25519"
	}
	return false
}

// check applies the key rules from the spec for using k with alg.
func (k *Key) check(alg string, private bool) error {
	if k.alg != "" && k.alg != alg {
		return fail(ErrInvalidKey, "key is bound to another algorithm")
	}
	if !k.fits(alg) {
		return fail(ErrInvalidKey, "key does not match algorithm "+alg)
	}
	if private && !k.IsPrivate() {
		return fail(ErrInvalidKey, "private key required")
	}
	if k.kty == "oct" {
		if h, ok := hashes[alg]; ok && len(k.secret) < h.Size() {
			return fail(ErrInvalidKey, "HMAC key too short for "+alg)
		}
		if n, ok := wrapSizes[alg]; ok && len(k.secret) != n {
			return fail(ErrInvalidKey, "wrong key length for "+alg)
		}
	}
	if k.kty == "RSA" && k.pub.(*rsa.PublicKey).N.BitLen() < 2048 {
		return fail(ErrInvalidKey, "RSA key must be at least 2048 bits")
	}
	return nil
}

func (k *Key) candidates(_, alg string, private bool) ([]*Key, error) {
	if err := k.check(alg, private); err != nil {
		return nil, err
	}
	return []*Key{k}, nil
}

func (k *Key) allows(alg string) bool {
	if k.alg != "" {
		return alg == k.alg
	}
	return k.fits(alg)
}

func (k *Key) ecdhPublic() (*ecdh.PublicKey, error) {
	switch p := k.pub.(type) {
	case *ecdsa.PublicKey:
		return p.ECDH()
	case *ecdh.PublicKey:
		return p, nil
	}
	return nil, fail(ErrInvalidKey, "key does not support ECDH")
}

func (k *Key) ecdhPrivate() (*ecdh.PrivateKey, error) {
	switch p := k.priv.(type) {
	case *ecdsa.PrivateKey:
		return p.ECDH()
	case *ecdh.PrivateKey:
		return p, nil
	}
	return nil, fail(ErrInvalidKey, "key does not support ECDH")
}

// randomBytes relies on crypto/rand.Read never failing (Go 1.24+).
func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
