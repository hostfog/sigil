package sigil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"slices"
	"strings"
)

var errDecrypt = errors.New("content decryption failed")

func encryptContent(enc string, cek, aad, plaintext []byte) (iv, ciphertext, tag []byte, err error) {
	if strings.HasSuffix(enc, "GCM") {
		gcm, err := newGCM(cek)
		if err != nil {
			return nil, nil, nil, err
		}
		iv = randomBytes(gcm.NonceSize())
		sealed := gcm.Seal(nil, iv, plaintext, aad)
		split := len(sealed) - gcm.Overhead()
		return iv, sealed[:split], sealed[split:], nil
	}

	macKey, encKey := cek[:len(cek)/2], cek[len(cek)/2:]
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, nil, err
	}
	iv = randomBytes(aes.BlockSize)
	pad := aes.BlockSize - len(plaintext)%aes.BlockSize
	ciphertext = make([]byte, len(plaintext)+pad)
	copy(ciphertext, plaintext)
	for i := len(plaintext); i < len(ciphertext); i++ {
		ciphertext[i] = byte(pad)
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, ciphertext)
	return iv, ciphertext, cbcTag(enc, macKey, aad, iv, ciphertext), nil
}

func decryptContent(enc string, cek, iv, ciphertext, tag, aad []byte) ([]byte, error) {
	if strings.HasSuffix(enc, "GCM") {
		gcm, err := newGCM(cek)
		if err != nil {
			return nil, err
		}
		if len(iv) != gcm.NonceSize() || len(tag) != gcm.Overhead() {
			return nil, errDecrypt
		}
		return gcm.Open(nil, iv, slices.Concat(ciphertext, tag), aad)
	}

	macKey, encKey := cek[:len(cek)/2], cek[len(cek)/2:]
	if !hmac.Equal(tag, cbcTag(enc, macKey, aad, iv, ciphertext)) {
		return nil, errDecrypt
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errDecrypt
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	pad := int(plaintext[len(plaintext)-1])
	if pad == 0 || pad > aes.BlockSize {
		return nil, errDecrypt
	}
	for _, b := range plaintext[len(plaintext)-pad:] {
		if int(b) != pad {
			return nil, errDecrypt
		}
	}
	return plaintext[:len(plaintext)-pad], nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// cbcTag computes the AES_CBC_HMAC_SHA2 authentication tag (RFC 7518 §5.2.2.1).
func cbcTag(enc string, macKey, aad, iv, ciphertext []byte) []byte {
	var h func() hash.Hash
	switch enc {
	case A128CBCHS256:
		h = sha256.New
	case A192CBCHS384:
		h = sha512.New384
	default:
		h = sha512.New
	}
	mac := hmac.New(h, macKey)
	mac.Write(aad)
	mac.Write(iv)
	mac.Write(ciphertext)
	mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(aad))*8))
	return mac.Sum(nil)[:len(macKey)]
}
