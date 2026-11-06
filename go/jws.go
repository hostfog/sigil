package sigil

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"strings"
)

// Sign encodes claims as a JWS compact token signed with key.
func Sign(claims any, key *Key, opts ...SignOption) (string, error) {
	if key == nil {
		return "", fail(ErrInvalidKey, "no key")
	}
	c := newTokenConfig(key)
	for _, opt := range opts {
		opt.applySign(c)
	}
	alg := c.alg
	if alg == "" {
		alg = key.defaultAlg()
	}
	if !isJWS(alg) {
		return "", fail(ErrUnsupportedAlg, "unsupported JWS algorithm")
	}
	if err := key.check(alg, true); err != nil {
		return "", err
	}
	payload, err := marshalClaims(claims)
	if err != nil {
		return "", err
	}
	header, err := c.header(alg, "", c.extra)
	if err != nil {
		return "", err
	}
	input := b64encode(header) + "." + b64encode(payload)
	sig, err := sign(key, alg, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64encode(sig), nil
}

// Verify checks a JWS compact token against keys and the given options
// and returns its header and claims.
func Verify(token string, keys KeySource, opts ...VerifyOption) (*Token, error) {
	cfg := newVerifyConfig(opts)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fail(ErrMalformed, "JWS must have 3 parts")
	}
	header, err := parseHeader(parts[0])
	if err != nil {
		return nil, err
	}
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, err
	}
	claims, err := parseObject(payload)
	if err != nil {
		return nil, err
	}
	sig, err := decodeSegment(parts[2])
	if err != nil {
		return nil, err
	}
	alg, kid, err := checkHeader(header, jwsAlgs, keys, cfg)
	if err != nil {
		return nil, err
	}
	candidates, err := keys.candidates(kid, alg, false)
	if err != nil {
		return nil, err
	}
	input := []byte(parts[0] + "." + parts[1])
	verified := false
	for _, k := range candidates {
		if verified = verifySignature(k, alg, input, sig); verified {
			break
		}
	}
	if !verified {
		return nil, fail(ErrInvalidSignature, "signature does not verify")
	}
	if err := cfg.validate(header, claims); err != nil {
		return nil, err
	}
	return &Token{Header: header, Claims: claims}, nil
}

func isJWS(alg string) bool {
	_, hashed := hashes[alg]
	return hashed || alg == EdDSA
}

func sign(k *Key, alg string, input []byte) ([]byte, error) {
	switch alg[:2] {
	case "HS":
		mac := hmac.New(hashes[alg].New, k.secret)
		mac.Write(input)
		return mac.Sum(nil), nil
	case "RS":
		return rsa.SignPKCS1v15(rand.Reader, k.priv.(*rsa.PrivateKey), hashes[alg], digest(alg, input))
	case "PS":
		return rsa.SignPSS(rand.Reader, k.priv.(*rsa.PrivateKey), hashes[alg], digest(alg, input),
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "ES":
		priv := k.priv.(*ecdsa.PrivateKey)
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest(alg, input))
		if err != nil {
			return nil, err
		}
		size := ecCurves[k.crv].size
		sig := make([]byte, 2*size)
		r.FillBytes(sig[:size])
		s.FillBytes(sig[size:])
		return sig, nil
	}
	return ed25519.Sign(k.priv.(ed25519.PrivateKey), input), nil
}

func verifySignature(k *Key, alg string, input, sig []byte) bool {
	switch alg[:2] {
	case "HS":
		mac := hmac.New(hashes[alg].New, k.secret)
		mac.Write(input)
		return hmac.Equal(sig, mac.Sum(nil))
	case "RS":
		return rsa.VerifyPKCS1v15(k.pub.(*rsa.PublicKey), hashes[alg], digest(alg, input), sig) == nil
	case "PS":
		return rsa.VerifyPSS(k.pub.(*rsa.PublicKey), hashes[alg], digest(alg, input), sig,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	case "ES":
		size := ecCurves[k.crv].size
		if len(sig) != 2*size {
			return false
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		return ecdsa.Verify(k.pub.(*ecdsa.PublicKey), digest(alg, input), r, s)
	}
	return ed25519.Verify(k.pub.(ed25519.PublicKey), input, sig)
}

func digest(alg string, input []byte) []byte {
	h := hashes[alg].New()
	h.Write(input)
	return h.Sum(nil)
}
