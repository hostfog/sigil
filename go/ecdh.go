package sigil

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
)

// agreeSender runs the sender side of ECDH-ES against the recipient key.
// It returns the derived key and the ephemeral public key for the epk header.
func agreeSender(recipient *Key, algID string, size int, apu, apv []byte) ([]byte, *jwk, error) {
	pub, err := recipient.ecdhPublic()
	if err != nil {
		return nil, nil, err
	}
	eph, err := generateCurve(recipient.crv)
	if err != nil {
		return nil, nil, err
	}
	priv, err := eph.ecdhPrivate()
	if err != nil {
		return nil, nil, err
	}
	z, err := priv.ECDH(pub)
	if err != nil {
		return nil, nil, fail(ErrInvalidKey, "ECDH failed")
	}
	return concatKDF(z, algID, apu, apv, size), eph.jwk(false), nil
}

// agreeRecipient runs the recipient side of ECDH-ES using the epk header.
func agreeRecipient(recipient *Key, header map[string]any, algID string, size int, apu, apv []byte) ([]byte, error) {
	raw, ok := header["epk"].(map[string]any)
	if !ok {
		return nil, fail(ErrMalformed, "missing epk header")
	}
	b, _ := json.Marshal(raw)
	epk, err := ParseJWK(b)
	if err != nil || epk.IsPrivate() {
		return nil, fail(ErrMalformed, "invalid epk header")
	}
	if epk.crv != recipient.crv {
		return nil, fail(ErrInvalidKey, "epk curve does not match the key")
	}
	pub, err := epk.ecdhPublic()
	if err != nil {
		return nil, err
	}
	priv, err := recipient.ecdhPrivate()
	if err != nil {
		return nil, err
	}
	z, err := priv.ECDH(pub)
	if err != nil {
		return nil, fail(ErrInvalidSignature, "ECDH failed")
	}
	return concatKDF(z, algID, apu, apv, size), nil
}

// concatKDF is the single-step KDF of NIST SP 800-56A as profiled by RFC 7518 §4.6.2.
func concatKDF(z []byte, algID string, apu, apv []byte, size int) []byte {
	var info []byte
	for _, field := range [][]byte{[]byte(algID), apu, apv} {
		info = binary.BigEndian.AppendUint32(info, uint32(len(field)))
		info = append(info, field...)
	}
	info = binary.BigEndian.AppendUint32(info, uint32(size*8))

	var out []byte
	for counter := uint32(1); len(out) < size; counter++ {
		h := sha256.New()
		h.Write(binary.BigEndian.AppendUint32(nil, counter))
		h.Write(z)
		h.Write(info)
		out = h.Sum(out)
	}
	return out[:size]
}
