package sigil

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// AES key wrap, RFC 3394.

var kwIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

var errUnwrap = errors.New("aes key unwrap failed")

func wrapKey(kek, key []byte) ([]byte, error) {
	if len(key) < 16 || len(key)%8 != 0 {
		return nil, errors.New("aes key wrap: invalid key length")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(key) / 8
	out := make([]byte, 8+len(key))
	copy(out, kwIV)
	copy(out[8:], key)
	var b [16]byte
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(b[:8], out[:8])
			copy(b[8:], out[8*i:])
			block.Encrypt(b[:], b[:])
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(out[:8], binary.BigEndian.Uint64(b[:8])^t)
			copy(out[8*i:], b[8:])
		}
	}
	return out, nil
}

func unwrapKey(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, errUnwrap
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(wrapped)/8 - 1
	out := make([]byte, len(wrapped))
	copy(out, wrapped)
	var b [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(out[:8])^t)
			copy(b[8:], out[8*i:])
			block.Decrypt(b[:], b[:])
			copy(out[:8], b[:8])
			copy(out[8*i:], b[8:])
		}
	}
	if subtle.ConstantTimeCompare(out[:8], kwIV) != 1 {
		return nil, errUnwrap
	}
	return out[8:], nil
}
