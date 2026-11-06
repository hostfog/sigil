package sigil

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
)

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	K   string `json:"k,omitempty"`
	D   string `json:"d,omitempty"`
	P   string `json:"p,omitempty"`
	Q   string `json:"q,omitempty"`
	DP  string `json:"dp,omitempty"`
	DQ  string `json:"dq,omitempty"`
	QI  string `json:"qi,omitempty"`
}

var errBadJWK = fail(ErrInvalidKey, "invalid JWK")

// ParseJWK parses a single JSON Web Key.
func ParseJWK(data []byte, opts ...KeyOption) (*Key, error) {
	var j jwk
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, errBadJWK
	}
	k, err := j.key()
	if err != nil {
		return nil, err
	}
	k.apply(opts)
	return k, nil
}

func (j *jwk) key() (*Key, error) {
	var k *Key
	var err error
	switch j.Kty {
	case "oct":
		var secret []byte
		if secret, err = b64decode(j.K); err == nil && len(secret) == 0 {
			err = errBadJWK
		}
		k = &Key{kty: "oct", secret: secret}
	case "RSA":
		k, err = j.rsaKey()
	case "EC":
		k, err = j.ecKey()
	case "OKP":
		k, err = j.okpKey()
	default:
		return nil, fail(ErrInvalidKey, "unsupported key type")
	}
	if err != nil {
		return nil, errBadJWK
	}
	k.kid, k.alg = j.Kid, j.Alg
	return k, nil
}

func (j *jwk) rsaKey() (*Key, error) {
	n, err := b64int(j.N)
	if err != nil {
		return nil, err
	}
	e, err := b64int(j.E)
	if err != nil || e.BitLen() > 31 {
		return nil, errBadJWK
	}
	pub := &rsa.PublicKey{N: n, E: int(e.Int64())}
	if j.D == "" {
		return fromCrypto(pub)
	}
	d, errD := b64int(j.D)
	p, errP := b64int(j.P)
	q, errQ := b64int(j.Q)
	if err := errors.Join(errD, errP, errQ); err != nil {
		return nil, err
	}
	priv := &rsa.PrivateKey{PublicKey: *pub, D: d, Primes: []*big.Int{p, q}}
	if err := priv.Validate(); err != nil {
		return nil, err
	}
	priv.Precompute()
	return fromCrypto(priv)
}

func (j *jwk) ecKey() (*Key, error) {
	c, ok := ecCurves[j.Crv]
	if !ok {
		return nil, errBadJWK
	}
	x, err := b64decode(j.X)
	if err != nil {
		return nil, err
	}
	y, err := b64decode(j.Y)
	if err != nil || len(x) != c.size || len(y) != c.size {
		return nil, errBadJWK
	}
	point := append(append([]byte{4}, x...), y...)
	if _, err := c.dh.NewPublicKey(point); err != nil {
		return nil, err
	}
	pub := &ecdsa.PublicKey{Curve: c.ec, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if j.D == "" {
		return fromCrypto(pub)
	}
	d, err := b64decode(j.D)
	if err != nil || len(d) != c.size {
		return nil, errBadJWK
	}
	dk, err := c.dh.NewPrivateKey(d)
	if err != nil || !bytes.Equal(dk.PublicKey().Bytes(), point) {
		return nil, errBadJWK
	}
	return fromCrypto(&ecdsa.PrivateKey{PublicKey: *pub, D: new(big.Int).SetBytes(d)})
}

func (j *jwk) okpKey() (*Key, error) {
	x, err := b64decode(j.X)
	if err != nil {
		return nil, err
	}
	var d []byte
	if j.D != "" {
		if d, err = b64decode(j.D); err != nil {
			return nil, err
		}
	}
	switch j.Crv {
	case "Ed25519":
		if len(x) != ed25519.PublicKeySize {
			return nil, errBadJWK
		}
		if d == nil {
			return fromCrypto(ed25519.PublicKey(x))
		}
		if len(d) != ed25519.SeedSize {
			return nil, errBadJWK
		}
		priv := ed25519.NewKeyFromSeed(d)
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), x) {
			return nil, errBadJWK
		}
		return fromCrypto(priv)
	case "X25519":
		pub, err := ecdh.X25519().NewPublicKey(x)
		if err != nil {
			return nil, err
		}
		if d == nil {
			return fromCrypto(pub)
		}
		priv, err := ecdh.X25519().NewPrivateKey(d)
		if err != nil || !priv.PublicKey().Equal(pub) {
			return nil, errBadJWK
		}
		return fromCrypto(priv)
	}
	return nil, errBadJWK
}

// JWK returns the key as a JSON Web Key. Private members are included only
// when includePrivate is true; a symmetric key has no public form.
func (k *Key) JWK(includePrivate bool) ([]byte, error) {
	if k.kty == "oct" && !includePrivate {
		return nil, fail(ErrInvalidKey, "symmetric key has no public form")
	}
	return json.Marshal(k.jwk(includePrivate))
}

func (k *Key) jwk(includePrivate bool) *jwk {
	j := &jwk{Kty: k.kty, Kid: k.kid, Alg: k.alg, Crv: k.crv}
	switch pub := k.pub.(type) {
	case *rsa.PublicKey:
		j.N = b64encode(pub.N.Bytes())
		j.E = b64encode(big.NewInt(int64(pub.E)).Bytes())
	case *ecdsa.PublicKey:
		// ECDH bytes give fixed-width coordinates; the key was validated on construction.
		point, _ := pub.ECDH()
		xy := point.Bytes()[1:]
		j.X, j.Y = b64encode(xy[:len(xy)/2]), b64encode(xy[len(xy)/2:])
	case ed25519.PublicKey:
		j.X = b64encode(pub)
	case *ecdh.PublicKey:
		j.X = b64encode(pub.Bytes())
	}
	if !includePrivate {
		return j
	}
	switch priv := k.priv.(type) {
	case *rsa.PrivateKey:
		j.D = b64encode(priv.D.Bytes())
		j.P = b64encode(priv.Primes[0].Bytes())
		j.Q = b64encode(priv.Primes[1].Bytes())
		j.DP = b64encode(priv.Precomputed.Dp.Bytes())
		j.DQ = b64encode(priv.Precomputed.Dq.Bytes())
		j.QI = b64encode(priv.Precomputed.Qinv.Bytes())
	case *ecdsa.PrivateKey:
		d, _ := priv.ECDH()
		j.D = b64encode(d.Bytes())
	case ed25519.PrivateKey:
		j.D = b64encode(priv.Seed())
	case *ecdh.PrivateKey:
		j.D = b64encode(priv.Bytes())
	}
	if k.kty == "oct" {
		j.K = b64encode(k.secret)
	}
	return j
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint, base64url encoded.
func (k *Key) Thumbprint() string {
	j := k.jwk(true)
	// Members must appear in lexicographic order.
	var members any
	switch k.kty {
	case "oct":
		members = struct {
			K   string `json:"k"`
			Kty string `json:"kty"`
		}{j.K, j.Kty}
	case "RSA":
		members = struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{j.E, j.Kty, j.N}
	case "EC":
		members = struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{j.Crv, j.Kty, j.X, j.Y}
	case "OKP":
		members = struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
		}{j.Crv, j.Kty, j.X}
	}
	b, _ := json.Marshal(members)
	sum := sha256.Sum256(b)
	return b64encode(sum[:])
}

func b64encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func b64int(s string) (*big.Int, error) {
	b, err := b64decode(s)
	if err != nil || len(b) == 0 {
		return nil, errBadJWK
	}
	return new(big.Int).SetBytes(b), nil
}
