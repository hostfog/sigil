package sigil_test

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	sigil "github.com/hostfog/sigil/go"
)

func pemKey(t *testing.T, typ string, der []byte) *sigil.Key {
	t.Helper()
	key, err := sigil.ParsePEM(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
	if err != nil {
		t.Fatalf("%s: %v", typ, err)
	}
	return key
}

func mustPKCS1(k *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(k)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestPEMTestdata(t *testing.T) {
	want := testKey(t, "rsa-2048").Thumbprint()

	priv, err := sigil.ParsePEM(readTestdata(t, "rsa-2048.pem"), sigil.KeyID("rsa-2048"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := sigil.ParsePEM(readTestdata(t, "rsa-2048.pub.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !priv.IsPrivate() || pub.IsPrivate() || priv.ID() != "rsa-2048" {
		t.Fatal("unexpected key properties")
	}
	if priv.Thumbprint() != want || pub.Thumbprint() != want {
		t.Fatal("PEM keys do not match keys.json")
	}
	token, err := sigil.Sign(claims, priv, sigil.WithAlgorithm(sigil.PS256))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sigil.Verify(token, pub); err != nil {
		t.Fatal(err)
	}
}

func TestPEMFormats(t *testing.T) {
	rsaKey := must(rsa.GenerateKey(rand.Reader, 2048))
	ecKey := must(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	_, edKey := must2(ed25519.GenerateKey(rand.Reader))
	xKey := must(ecdh.X25519().GenerateKey(rand.Reader))

	tests := []struct {
		name    string
		typ     string
		der     []byte
		kty     string
		crv     string
		private bool
	}{
		{"PKCS#8 RSA", "PRIVATE KEY", must(x509.MarshalPKCS8PrivateKey(rsaKey)), "RSA", "", true},
		{"PKCS#8 EC", "PRIVATE KEY", must(x509.MarshalPKCS8PrivateKey(ecKey)), "EC", "P-384", true},
		{"PKCS#8 Ed25519", "PRIVATE KEY", must(x509.MarshalPKCS8PrivateKey(edKey)), "OKP", "Ed25519", true},
		{"PKCS#8 X25519", "PRIVATE KEY", must(x509.MarshalPKCS8PrivateKey(xKey)), "OKP", "X25519", true},
		{"PKCS#1", "RSA PRIVATE KEY", mustPKCS1(rsaKey), "RSA", "", true},
		{"SEC1", "EC PRIVATE KEY", must(x509.MarshalECPrivateKey(ecKey)), "EC", "P-384", true},
		{"SPKI RSA", "PUBLIC KEY", must(x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)), "RSA", "", false},
		{"SPKI EC", "PUBLIC KEY", must(x509.MarshalPKIXPublicKey(&ecKey.PublicKey)), "EC", "P-384", false},
		{"SPKI Ed25519", "PUBLIC KEY", must(x509.MarshalPKIXPublicKey(edKey.Public())), "OKP", "Ed25519", false},
		{"certificate", "CERTIFICATE", selfSigned(t, ecKey), "EC", "P-384", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := pemKey(t, tt.typ, tt.der)
			if key.Type() != tt.kty || key.Curve() != tt.crv || key.IsPrivate() != tt.private {
				t.Fatalf("got %s %s private=%v", key.Type(), key.Curve(), key.IsPrivate())
			}
		})
	}
}

func TestPEMSkipsECParameters(t *testing.T) {
	ecKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: must(x509.MarshalECPrivateKey(ecKey))})...)
	key, err := sigil.ParsePEM(data)
	if err != nil {
		t.Fatal(err)
	}
	if key.Curve() != "P-256" || !key.IsPrivate() {
		t.Fatal("unexpected key")
	}
}

func TestPEMRejectsGarbage(t *testing.T) {
	for _, data := range []string{"", "not pem", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"} {
		_, err := sigil.ParsePEM([]byte(data))
		wantErr(t, err, sigil.ErrInvalidKey)
	}
}

func selfSigned(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sigil"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), crypto.Signer(key))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}
