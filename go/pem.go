package sigil

import (
	"crypto/x509"
	"encoding/pem"
)

// ParsePEM parses the first key in PEM data: a PKCS#8, PKCS#1 RSA or SEC1 EC
// private key, an SPKI public key, or the public key of an X.509 certificate.
func ParsePEM(data []byte, opts ...KeyOption) (*Key, error) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, fail(ErrInvalidKey, "no PEM key found")
		}
		data = rest

		var key any
		var err error
		switch block.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		case "PUBLIC KEY":
			key, err = x509.ParsePKIXPublicKey(block.Bytes)
		case "CERTIFICATE":
			var cert *x509.Certificate
			if cert, err = x509.ParseCertificate(block.Bytes); err == nil {
				key = cert.PublicKey
			}
		default:
			continue
		}
		if err != nil {
			return nil, fail(ErrInvalidKey, "invalid PEM key")
		}
		k, err := fromCrypto(key)
		if err != nil {
			return nil, err
		}
		k.apply(opts)
		return k, nil
	}
}
