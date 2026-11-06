package sigil_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	sigil "github.com/hostfog/sigil/go"
)

var claims = map[string]any{"sub": "u1"}

func TestAlgorithmKeyConfusion(t *testing.T) {
	rsaPub := testKey(t, "rsa-2048").Public()
	jwk, err := rsaPub.JWK(false)
	if err != nil {
		t.Fatal(err)
	}
	// The classic attack: HMAC-sign with the RSA public key bytes.
	token := forgeHS256(`{"alg":"HS256"}`, `{"sub":"admin"}`, jwk)

	_, err = sigil.Verify(token, rsaPub)
	wantErr(t, err, sigil.ErrUnsupportedAlg)
	_, err = sigil.Verify(token, rsaPub, sigil.Algorithms(sigil.HS256))
	wantErr(t, err, sigil.ErrInvalidKey)
}

func TestKeyAlgorithmMismatch(t *testing.T) {
	tests := []struct {
		name string
		key  string
		alg  string
	}{
		{"HS with RSA", "rsa-2048", sigil.HS256},
		{"RS with EC", "ec-p256", sigil.RS256},
		{"ES256 with P-384", "ec-p384", sigil.ES256},
		{"ES512 with P-256", "ec-p256", sigil.ES512},
		{"EdDSA with X25519", "x25519", sigil.EdDSA},
		{"ES256 with Ed25519", "ed25519", sigil.ES256},
		{"PS with secret", "oct-hs512", sigil.PS256},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sigil.Sign(claims, testKey(t, tt.key), sigil.WithAlgorithm(tt.alg))
			wantErr(t, err, sigil.ErrInvalidKey)
		})
	}

	_, err := sigil.Encrypt(claims, testKey(t, "ed25519").Public(), sigil.WithKeyAlgorithm(sigil.ECDHES))
	wantErr(t, err, sigil.ErrInvalidKey)
	_, err = sigil.Encrypt(claims, testKey(t, "ec-p256").Public(), sigil.WithKeyAlgorithm(sigil.RSAOAEP))
	wantErr(t, err, sigil.ErrInvalidKey)
}

func TestBoundAlgorithm(t *testing.T) {
	key := sigil.NewSecret(secret(64), sigil.KeyAlgorithm(sigil.HS512))
	token, err := sigil.Sign(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	if tok, _ := sigil.Decode(token); tok.Header["alg"] != sigil.HS512 {
		t.Fatalf("alg = %v, want HS512", tok.Header["alg"])
	}
	_, err = sigil.Sign(claims, key, sigil.WithAlgorithm(sigil.HS256))
	wantErr(t, err, sigil.ErrInvalidKey)

	other, _ := sigil.Sign(claims, sigil.NewSecret(secret(64)), sigil.WithAlgorithm(sigil.HS256))
	_, err = sigil.Verify(other, key)
	wantErr(t, err, sigil.ErrUnsupportedAlg)
	_, err = sigil.Verify(other, key, sigil.Algorithms(sigil.HS256))
	wantErr(t, err, sigil.ErrInvalidKey)
}

func TestShortHMACKey(t *testing.T) {
	for alg, size := range map[string]int{sigil.HS256: 32, sigil.HS384: 48, sigil.HS512: 64} {
		_, err := sigil.Sign(claims, sigil.NewSecret(secret(size-1)), sigil.WithAlgorithm(alg))
		wantErr(t, err, sigil.ErrInvalidKey)
		if _, err := sigil.Sign(claims, sigil.NewSecret(secret(size)), sigil.WithAlgorithm(alg)); err != nil {
			t.Fatalf("%s with %d bytes: %v", alg, size, err)
		}
	}
	token := forgeHS256(`{"alg":"HS256"}`, `{}`, secret(16))
	_, err := sigil.Verify(token, sigil.NewSecret(secret(16)))
	wantErr(t, err, sigil.ErrInvalidKey)
}

func TestSmallRSAKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	key := pemKey(t, "RSA PRIVATE KEY", mustPKCS1(priv))
	_, err = sigil.Sign(claims, key)
	wantErr(t, err, sigil.ErrInvalidKey)
	_, err = sigil.Encrypt(claims, key, sigil.WithKeyAlgorithm(sigil.RSAOAEP256))
	wantErr(t, err, sigil.ErrInvalidKey)
	_, err = sigil.Verify("eyJhbGciOiJSUzI1NiJ9.e30.AA", key)
	wantErr(t, err, sigil.ErrInvalidKey)
}

func TestPrivateKeyRequired(t *testing.T) {
	_, err := sigil.Sign(claims, testKey(t, "ec-p256").Public())
	wantErr(t, err, sigil.ErrInvalidKey)

	pub := testKey(t, "rsa-2048").Public()
	token, err := sigil.Encrypt(claims, pub, sigil.WithKeyAlgorithm(sigil.RSAOAEP))
	if err != nil {
		t.Fatal(err)
	}
	_, err = sigil.Decrypt(token, pub)
	wantErr(t, err, sigil.ErrInvalidKey)
}

func TestSymmetricKeyLengths(t *testing.T) {
	_, err := sigil.Encrypt(claims, testKey(t, "dir-a128gcm"), sigil.WithKeyAlgorithm(sigil.Dir))
	wantErr(t, err, sigil.ErrInvalidKey)
	_, err = sigil.Encrypt(claims, testKey(t, "oct-hs256"), sigil.WithKeyAlgorithm(sigil.A128KW))
	wantErr(t, err, sigil.ErrInvalidKey)

	token, err := sigil.Encrypt(claims, testKey(t, "dir-a128gcm"), sigil.WithKeyAlgorithm(sigil.Dir), sigil.WithEncryption(sigil.A128GCM))
	if err != nil {
		t.Fatal(err)
	}
	_, err = sigil.Decrypt(token, testKey(t, "dir-a256gcm"), sigil.Algorithms(sigil.Dir))
	wantErr(t, err, sigil.ErrInvalidKey)
}

func TestEncryptNeedsAlgorithm(t *testing.T) {
	_, err := sigil.Encrypt(claims, testKey(t, "oct-a128kw"))
	wantErr(t, err, sigil.ErrUnsupportedAlg)
	_, err = sigil.Encrypt(claims, testKey(t, "oct-a128kw"), sigil.WithKeyAlgorithm(sigil.A128KW), sigil.WithEncryption("A512GCM"))
	wantErr(t, err, sigil.ErrUnsupportedAlg)

	key := sigil.NewSecret(secret(32), sigil.KeyAlgorithm(sigil.Dir))
	token, err := sigil.Encrypt(claims, key)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := sigil.Decrypt(token, key)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Header["alg"] != sigil.Dir || tok.Header["enc"] != sigil.A256GCM {
		t.Fatalf("header = %v", tok.Header)
	}
}

func TestDefaultSignAlgorithm(t *testing.T) {
	want := map[string]string{
		"oct-hs256": sigil.HS256, "rsa-2048": sigil.RS256, "ec-p256": sigil.ES256,
		"ec-p384": sigil.ES384, "ec-p521": sigil.ES512, "ed25519": sigil.EdDSA,
	}
	for kid, alg := range want {
		token, err := sigil.Sign(claims, testKey(t, kid))
		if err != nil {
			t.Fatal(err)
		}
		tok, err := sigil.Verify(token, testKey(t, kid))
		if err != nil {
			t.Fatal(err)
		}
		if tok.Header["alg"] != alg {
			t.Errorf("%s signed with %v, want %s", kid, tok.Header["alg"], alg)
		}
	}
}

func TestGenerateKey(t *testing.T) {
	for _, alg := range []string{
		sigil.HS256, sigil.HS384, sigil.HS512, sigil.RS256, sigil.PS512,
		sigil.ES256, sigil.ES384, sigil.ES512, sigil.EdDSA,
	} {
		key, err := sigil.GenerateKey(alg, sigil.KeyID("gen"))
		if err != nil {
			t.Fatal(err)
		}
		token, err := sigil.Sign(claims, key)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if _, err := sigil.Verify(token, key); err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
	}
	for _, alg := range []string{
		sigil.A128KW, sigil.A192KW, sigil.A256KW, sigil.RSAOAEP, sigil.RSAOAEP256,
		sigil.ECDHES, sigil.ECDHESA128KW, sigil.ECDHESA256KW,
	} {
		key, err := sigil.GenerateKey(alg)
		if err != nil {
			t.Fatal(err)
		}
		token, err := sigil.Encrypt(claims, key)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if _, err := sigil.Decrypt(token, key); err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
	}
	key, err := sigil.GenerateKey(sigil.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if key.Algorithm() != sigil.Dir {
		t.Fatalf("generated key bound to %q", key.Algorithm())
	}
	for _, enc := range []string{sigil.A256GCM, sigil.A128CBCHS256} {
		token, err := sigil.Encrypt(claims, key, sigil.WithEncryption(enc))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sigil.Decrypt(token, key); err != nil {
			t.Fatal(err)
		}
	}

	_, err = sigil.GenerateKey("none")
	wantErr(t, err, sigil.ErrUnsupportedAlg)
}

func TestJWKRoundTrip(t *testing.T) {
	var doc struct{ Keys []map[string]string }
	if err := json.Unmarshal(readTestdata(t, "keys.json"), &doc); err != nil {
		t.Fatal(err)
	}
	for _, want := range doc.Keys {
		b, _ := json.Marshal(want)
		key, err := sigil.ParseJWK(b)
		if err != nil {
			t.Fatalf("%s: %v", want["kid"], err)
		}
		out, err := key.JWK(true)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]string
		json.Unmarshal(out, &got)
		sameJSON(t, got, want)

		if key.Type() != want["kty"] || key.ID() != want["kid"] || key.Curve() != want["crv"] || !key.IsPrivate() {
			t.Fatalf("%s: accessors disagree with the JWK", want["kid"])
		}
		if key.Type() == "oct" {
			if key.Public() != nil {
				t.Fatal("symmetric key has a public form")
			}
			_, err := key.JWK(false)
			wantErr(t, err, sigil.ErrInvalidKey)
			continue
		}
		pub := key.Public()
		if pub.IsPrivate() || pub.Thumbprint() != key.Thumbprint() {
			t.Fatalf("%s: bad public key", want["kid"])
		}
		out, _ = pub.JWK(false)
		var public map[string]string
		json.Unmarshal(out, &public)
		if _, ok := public["d"]; ok {
			t.Fatalf("%s: public JWK has d", want["kid"])
		}
	}
}

func TestParseJWKRejectsBadKeys(t *testing.T) {
	for _, jwk := range []string{
		`{"kty":"oct","k":""}`,
		`{"kty":"oct","k":"!!"}`,
		`{"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA"}`,
		`{"kty":"EC","crv":"secp256k1","x":"AA","y":"AA"}`,
		`{"kty":"OKP","crv":"Ed448","x":"AA"}`,
		`{"kty":"RSA","n":"","e":"AQAB"}`,
		`{"kty":"foo"}`,
		`not json`,
	} {
		_, err := sigil.ParseJWK([]byte(jwk))
		wantErr(t, err, sigil.ErrInvalidKey)
	}
}

func TestKeyOptions(t *testing.T) {
	key, err := sigil.ParseJWK(readKeyJSON(t, "ec-p256"), sigil.KeyID("override"), sigil.KeyAlgorithm(sigil.ECDHES))
	if err != nil {
		t.Fatal(err)
	}
	if key.ID() != "override" || key.Algorithm() != sigil.ECDHES {
		t.Fatalf("kid %q alg %q", key.ID(), key.Algorithm())
	}
}

func readKeyJSON(t *testing.T, kid string) []byte {
	t.Helper()
	b, err := testKey(t, kid).JWK(true)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
