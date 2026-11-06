package sigil_test

import (
	"encoding/json"
	"testing"

	sigil "github.com/hostfog/sigil/go"
)

func TestParseJWKS(t *testing.T) {
	if n := len(testKeys(t).Keys()); n != 18 {
		t.Fatalf("keys.json has %d keys, want 18", n)
	}
	set, err := sigil.ParseJWKS([]byte(`{"keys":[
		{"kty":"foo"},
		{"kty":"OKP","crv":"Ed448","x":"AA"},
		{"kty":"EC","crv":"secp256k1","x":"AA","y":"AA"},
		{"kty":"oct","kid":"a","k":"c2VjcmV0"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys()) != 1 || set.Get("a") == nil || set.Get("b") != nil {
		t.Fatal("unsupported entries were not skipped")
	}
	_, err = sigil.ParseJWKS([]byte(`{"keys":[{"kty":"oct","k":""}]}`))
	wantErr(t, err, sigil.ErrInvalidKey)
}

func TestKeySetJSON(t *testing.T) {
	set := testKeys(t)
	var public struct{ Keys []map[string]any }
	b, err := set.JSON(false)
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(b, &public)
	if len(public.Keys) != 6 {
		t.Fatalf("public JWKS has %d keys, want 6", len(public.Keys))
	}
	for _, k := range public.Keys {
		if _, ok := k["d"]; ok || k["kty"] == "oct" {
			t.Fatalf("public JWKS leaks private material for %v", k["kid"])
		}
	}

	b, err = set.JSON(true)
	if err != nil {
		t.Fatal(err)
	}
	again, err := sigil.ParseJWKS(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range set.Keys() {
		if again.Get(k.ID()).Thumbprint() != k.Thumbprint() {
			t.Fatalf("%s did not round-trip", k.ID())
		}
	}
}

func TestKeySetSelection(t *testing.T) {
	set := testKeys(t)
	token, err := sigil.Sign(claims, set.Get("ec-p256"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sigil.Verify(token, set); err != nil {
		t.Fatal(err)
	}

	unknown, _ := sigil.Sign(claims, set.Get("ec-p256"), sigil.WithKeyID("missing"))
	_, err = sigil.Verify(unknown, set)
	wantErr(t, err, sigil.ErrKeyNotFound)

	wrongKid, _ := sigil.Sign(claims, set.Get("ec-p256"), sigil.WithKeyID("rsa-2048"), sigil.WithAlgorithm(sigil.ES256))
	_, err = sigil.Verify(wrongKid, set, sigil.Algorithms(sigil.ES256))
	wantErr(t, err, sigil.ErrInvalidKey)
}

func TestKeySetFallbackWithoutKid(t *testing.T) {
	set := testKeys(t)

	// Every 32+ byte secret is a candidate for HS256; only one verifies.
	token, err := sigil.Sign(claims, set.Get("oct-hs512"), sigil.WithAlgorithm(sigil.HS256), sigil.WithKeyID(""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sigil.Verify(token, set); err != nil {
		t.Fatal(err)
	}

	stranger, _ := sigil.Sign(claims, sigil.NewSecret(secret(32)), sigil.WithKeyID(""))
	_, err = sigil.Verify(stranger, set)
	wantErr(t, err, sigil.ErrInvalidSignature)

	onlyEC := &sigil.KeySet{}
	onlyEC.Add(set.Get("ec-p256"))
	_, err = sigil.Verify(stranger, onlyEC, sigil.Algorithms(sigil.HS256))
	wantErr(t, err, sigil.ErrKeyNotFound)

	// ECDH-ES candidates include keys on other curves, which must be skipped.
	jwe, err := sigil.Encrypt(claims, set.Get("x25519").Public(), sigil.WithKeyAlgorithm(sigil.ECDHES), sigil.WithKeyID(""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sigil.Decrypt(jwe, set); err != nil {
		t.Fatal(err)
	}
}
