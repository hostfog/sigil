package sigil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"hash"
	"maps"
	"slices"
	"strings"
)

// Encrypt encodes claims as a JWE compact token for key. The key management
// algorithm must be given with WithKeyAlgorithm unless the key is bound to one.
func Encrypt(claims any, key *Key, opts ...EncryptOption) (string, error) {
	if key == nil {
		return "", fail(ErrInvalidKey, "no key")
	}
	c := newTokenConfig(key)
	c.enc = A256GCM
	for _, opt := range opts {
		opt.applyEncrypt(c)
	}
	alg := c.alg
	if alg == "" && slices.Contains(jweAlgs, key.alg) {
		alg = key.alg
	}
	if !slices.Contains(jweAlgs, alg) {
		return "", fail(ErrUnsupportedAlg, "unsupported JWE algorithm")
	}
	if _, ok := encSizes[c.enc]; !ok {
		return "", fail(ErrUnsupportedAlg, "unsupported JWE encryption")
	}
	if err := key.check(alg, false); err != nil {
		return "", err
	}
	payload, err := marshalClaims(claims)
	if err != nil {
		return "", err
	}
	extra := maps.Clone(c.extra)
	cek, encryptedKey, err := encryptKey(key, alg, c.enc, extra)
	if err != nil {
		return "", err
	}
	header, err := c.header(alg, c.enc, extra)
	if err != nil {
		return "", err
	}
	protected := b64encode(header)
	iv, ciphertext, tag, err := encryptContent(c.enc, cek, []byte(protected), payload)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{
		protected, b64encode(encryptedKey), b64encode(iv), b64encode(ciphertext), b64encode(tag),
	}, "."), nil
}

// Decrypt decrypts a JWE compact token with keys, checks it against the
// given options and returns its header and claims.
func Decrypt(token string, keys KeySource, opts ...VerifyOption) (*Token, error) {
	cfg := newVerifyConfig(opts)
	parts := strings.Split(token, ".")
	if len(parts) != 5 {
		return nil, fail(ErrMalformed, "JWE must have 5 parts")
	}
	header, err := parseHeader(parts[0])
	if err != nil {
		return nil, err
	}
	segments := make([][]byte, 4)
	for i, part := range parts[1:] {
		if segments[i], err = decodeSegment(part); err != nil {
			return nil, err
		}
	}
	alg, kid, err := checkHeader(header, jweAlgs, keys, cfg)
	if err != nil {
		return nil, err
	}
	enc, _ := header["enc"].(string)
	if _, ok := encSizes[enc]; !ok {
		return nil, fail(ErrUnsupportedAlg, "unsupported JWE encryption")
	}
	candidates, err := keys.candidates(kid, alg, true)
	if err != nil {
		return nil, err
	}

	var plaintext []byte
	for _, k := range candidates {
		plaintext, err = decryptWith(k, alg, enc, header, segments, []byte(parts[0]))
		if err == nil || errors.Is(err, ErrMalformed) {
			break
		}
	}
	if err != nil {
		if len(candidates) > 1 && !errors.Is(err, ErrMalformed) {
			err = fail(ErrInvalidSignature, "no key decrypts the token")
		}
		return nil, err
	}
	claims, err := parseObject(plaintext)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(header, claims); err != nil {
		return nil, err
	}
	return &Token{Header: header, Claims: claims}, nil
}

// decryptWith decrypts the four non-header segments of a JWE with k.
func decryptWith(k *Key, alg, enc string, header map[string]any, segments [][]byte, aad []byte) ([]byte, error) {
	encryptedKey, iv, ciphertext, tag := segments[0], segments[1], segments[2], segments[3]
	cek, err := decryptKey(k, alg, enc, header, encryptedKey)
	if err != nil {
		return nil, err
	}
	if len(cek) != encSizes[enc] {
		return nil, fail(ErrInvalidSignature, "content key has the wrong length")
	}
	plaintext, err := decryptContent(enc, cek, iv, ciphertext, tag, aad)
	if err != nil {
		return nil, fail(ErrInvalidSignature, "decryption failed")
	}
	return plaintext, nil
}

// encryptKey produces the content key and its encrypted form. ECDH-ES
// algorithms add the epk parameter to header.
func encryptKey(k *Key, alg, enc string, header map[string]any) (cek, encryptedKey []byte, err error) {
	size := encSizes[enc]
	switch alg {
	case Dir:
		if len(k.secret) != size {
			return nil, nil, fail(ErrInvalidKey, "wrong key length for "+enc)
		}
		return k.secret, nil, nil
	case A128KW, A192KW, A256KW:
		cek = randomBytes(size)
		encryptedKey, err = wrapKey(k.secret, cek)
		return cek, encryptedKey, err
	case RSAOAEP, RSAOAEP256:
		cek = randomBytes(size)
		encryptedKey, err = rsa.EncryptOAEP(oaepHash(alg), rand.Reader, k.pub.(*rsa.PublicKey), cek, nil)
		return cek, encryptedKey, err
	}

	apu, apv, err := partyInfo(header)
	if err != nil {
		return nil, nil, err
	}
	algID, derivedSize := ecdhParams(alg, enc)
	derived, epk, err := agreeSender(k, algID, derivedSize, apu, apv)
	if err != nil {
		return nil, nil, err
	}
	header["epk"] = epk
	if alg == ECDHES {
		return derived, nil, nil
	}
	cek = randomBytes(size)
	encryptedKey, err = wrapKey(derived, cek)
	return cek, encryptedKey, err
}

func decryptKey(k *Key, alg, enc string, header map[string]any, encryptedKey []byte) ([]byte, error) {
	errKey := fail(ErrInvalidSignature, "key decryption failed")
	size := encSizes[enc]
	switch alg {
	case Dir:
		if len(encryptedKey) != 0 {
			return nil, fail(ErrMalformed, "dir token must not carry an encrypted key")
		}
		if len(k.secret) != size {
			return nil, fail(ErrInvalidKey, "wrong key length for "+enc)
		}
		return k.secret, nil
	case A128KW, A192KW, A256KW:
		cek, err := unwrapKey(k.secret, encryptedKey)
		if err != nil {
			return nil, errKey
		}
		return cek, nil
	case RSAOAEP, RSAOAEP256:
		cek, err := rsa.DecryptOAEP(oaepHash(alg), nil, k.priv.(*rsa.PrivateKey), encryptedKey, nil)
		if err != nil {
			// RFC 7516 §11.5: carry on with a random key so failures look alike.
			return randomBytes(size), nil
		}
		return cek, nil
	}

	apu, apv, err := partyInfo(header)
	if err != nil {
		return nil, err
	}
	if alg == ECDHES && len(encryptedKey) != 0 {
		return nil, fail(ErrMalformed, "ECDH-ES token must not carry an encrypted key")
	}
	algID, derivedSize := ecdhParams(alg, enc)
	derived, err := agreeRecipient(k, header, algID, derivedSize, apu, apv)
	if err != nil || alg == ECDHES {
		return derived, err
	}
	cek, err := unwrapKey(derived, encryptedKey)
	if err != nil {
		return nil, errKey
	}
	return cek, nil
}

// partyInfo reads the optional apu and apv header parameters.
func partyInfo(header map[string]any) (apu, apv []byte, err error) {
	read := func(name string) ([]byte, error) {
		v, ok := header[name]
		if !ok {
			return nil, nil
		}
		s, ok := v.(string)
		b, err := b64decode(s)
		if !ok || err != nil {
			return nil, fail(ErrMalformed, "invalid "+name+" header")
		}
		return b, nil
	}
	if apu, err = read("apu"); err != nil {
		return nil, nil, err
	}
	apv, err = read("apv")
	return apu, apv, err
}

// ecdhParams returns the Concat KDF AlgorithmID and output size: the content
// key for direct ECDH-ES, the key-encryption key for the key wrap variants.
func ecdhParams(alg, enc string) (string, int) {
	if alg == ECDHES {
		return enc, encSizes[enc]
	}
	return alg, wrapSizes[alg]
}

func oaepHash(alg string) hash.Hash {
	if alg == RSAOAEP {
		return sha1.New()
	}
	return sha256.New()
}
