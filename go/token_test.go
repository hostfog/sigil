package sigil_test

import (
	"encoding/base64"
	"strings"
	"testing"

	sigil "github.com/hostfog/sigil/go"
)

func TestNoneRejected(t *testing.T) {
	key := sigil.NewSecret(secret(32))
	keys := testKeys(t)
	for _, alg := range []string{"none", "None", "NONE", "nOnE"} {
		token := b64(`{"alg":"`+alg+`"}`) + "." + b64(`{}`) + "."
		_, err := sigil.Verify(token, key)
		wantErr(t, err, sigil.ErrUnsupportedAlg)
		_, err = sigil.Verify(token, keys, sigil.Algorithms(alg))
		wantErr(t, err, sigil.ErrUnsupportedAlg)
		_, err = sigil.Sign(claims, key, sigil.WithAlgorithm(alg))
		wantErr(t, err, sigil.ErrUnsupportedAlg)
	}
}

func TestCritAndZipRejected(t *testing.T) {
	key := sigil.NewSecret(secret(32))
	for _, header := range []string{
		`{"alg":"HS256","crit":["exp"],"exp":1}`,
		`{"alg":"HS256","zip":"DEF"}`,
	} {
		_, err := sigil.Verify(forgeHS256(header, `{}`, secret(32)), key)
		wantErr(t, err, sigil.ErrUnsupportedAlg)
	}

	dir := testKey(t, "dir-a256gcm")
	token, err := sigil.Encrypt(claims, dir, sigil.WithKeyAlgorithm(sigil.Dir))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	parts[0] = b64(`{"alg":"dir","enc":"A256GCM","zip":"DEF"}`)
	_, err = sigil.Decrypt(strings.Join(parts, "."), dir)
	wantErr(t, err, sigil.ErrUnsupportedAlg)
	parts[0] = b64(`{"alg":"dir","enc":"A512GCM"}`)
	_, err = sigil.Decrypt(strings.Join(parts, "."), dir)
	wantErr(t, err, sigil.ErrUnsupportedAlg)
}

func TestReservedHeadersCannotBeOverridden(t *testing.T) {
	key := sigil.NewSecret(secret(32), sigil.KeyID("k0"))
	token, err := sigil.Sign(claims, key,
		sigil.WithHeader("alg", "none"),
		sigil.WithHeader("crit", []string{"x"}),
		sigil.WithHeader("zip", "DEF"),
		sigil.WithHeader("x5t", "abc"),
		sigil.WithHeader("kid", "k1"),
		sigil.WithType("at+jwt"),
	)
	if err != nil {
		t.Fatal(err)
	}
	header, _ := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if want := `{"alg":"HS256","typ":"at+jwt","kid":"k1","x5t":"abc"}`; string(header) != want {
		t.Fatalf("header = %s, want %s", header, want)
	}
	if _, err := sigil.Verify(token, key, sigil.Type("AT+JWT")); err != nil {
		t.Fatal(err)
	}

	token, _ = sigil.Sign(claims, key, sigil.WithType(""), sigil.WithKeyID(""))
	header, _ = base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if string(header) != `{"alg":"HS256"}` {
		t.Fatalf("header = %s", header)
	}
}

func TestMalformed(t *testing.T) {
	key := sigil.NewSecret(secret(32))
	sig := strings.Split(forgeHS256(`{"alg":"HS256"}`, `{}`, secret(32)), ".")[2]
	for _, token := range []string{
		"",
		"abc",
		"a.b",
		"a.b.c.d",
		"!!!." + b64(`{}`) + "." + sig,
		b64(`not json`) + "." + b64(`{}`) + "." + sig,
		b64(`{"alg":"HS256"}`) + "." + b64(`[1]`) + "." + sig,
		b64(`{"alg":"HS256"}`) + "." + b64(`{} {}`) + "." + sig,
		b64(`{"alg":"HS256"}`) + "." + b64(`{}`) + ".!!",
		b64(`{}`) + "." + b64(`{}`) + "." + sig,
		b64(`{"alg":"HS256","kid":7}`) + "." + b64(`{}`) + "." + sig,
	} {
		_, err := sigil.Verify(token, key)
		wantErr(t, err, sigil.ErrMalformed)
	}

	jwe, err := sigil.Encrypt(claims, testKey(t, "oct-a128kw"), sigil.WithKeyAlgorithm(sigil.A128KW))
	if err != nil {
		t.Fatal(err)
	}
	jws, _ := sigil.Sign(claims, key)
	_, err = sigil.Verify(jwe, key)
	wantErr(t, err, sigil.ErrMalformed)
	_, err = sigil.Decrypt(jws, key)
	wantErr(t, err, sigil.ErrMalformed)
	_, err = sigil.Decode(jwe)
	wantErr(t, err, sigil.ErrMalformed)

	_, err = sigil.Sign([]int{1}, key)
	wantErr(t, err, sigil.ErrMalformed)
}

func TestECDHEphemeralKey(t *testing.T) {
	p256 := testKey(t, "ec-p256")
	token, err := sigil.Encrypt(claims, p256.Public(), sigil.WithKeyAlgorithm(sigil.ECDHES))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")

	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	epk := testKey(t, "ec-p384").Public()
	jwk, _ := epk.JWK(false)
	forged := strings.Replace(string(header), `"epk":{`, `"epk":`+string(jwk)+`,"old":{`, 1)
	parts[0] = b64(forged)
	_, err = sigil.Decrypt(strings.Join(parts, "."), p256)
	wantErr(t, err, sigil.ErrInvalidKey)

	parts[0] = b64(`{"alg":"ECDH-ES","enc":"A256GCM"}`)
	_, err = sigil.Decrypt(strings.Join(parts, "."), p256)
	wantErr(t, err, sigil.ErrMalformed)

	parts[0] = b64(`{"alg":"ECDH-ES","enc":"A256GCM","epk":{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}}`)
	_, err = sigil.Decrypt(strings.Join(parts, "."), p256)
	wantErr(t, err, sigil.ErrMalformed)
}

func TestApuApv(t *testing.T) {
	key := testKey(t, "x25519")
	token, err := sigil.Encrypt(claims, key.Public(), sigil.WithKeyAlgorithm(sigil.ECDHESA128KW),
		sigil.WithHeader("apu", b64("Alice")), sigil.WithHeader("apv", b64("Bob")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sigil.Decrypt(token, key); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	parts[0] = b64(strings.Replace(string(header), b64("Bob"), b64("Eve"), 1))
	_, err = sigil.Decrypt(strings.Join(parts, "."), key)
	wantErr(t, err, sigil.ErrInvalidSignature)
}

func TestRSAOAEPWrongKey(t *testing.T) {
	rsaKey := testKey(t, "rsa-2048")
	token, err := sigil.Encrypt(claims, rsaKey.Public(), sigil.WithKeyAlgorithm(sigil.RSAOAEP256))
	if err != nil {
		t.Fatal(err)
	}
	other, err := sigil.GenerateKey(sigil.RSAOAEP256)
	if err != nil {
		t.Fatal(err)
	}
	_, err = sigil.Decrypt(token, other)
	wantErr(t, err, sigil.ErrInvalidSignature)
}

func TestDecodeAndBind(t *testing.T) {
	key := sigil.NewSecret(secret(32))
	token, err := sigil.Sign(map[string]any{"sub": "u1", "exp": 1, "roles": []string{"a"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := sigil.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Sub   string   `json:"sub"`
		Exp   int64    `json:"exp"`
		Roles []string `json:"roles"`
	}
	if err := tok.Bind(&out); err != nil {
		t.Fatal(err)
	}
	if out.Sub != "u1" || out.Exp != 1 || len(out.Roles) != 1 || tok.Header["typ"] != "JWT" {
		t.Fatalf("decoded %+v %v", out, tok.Header)
	}
}

func b64(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
