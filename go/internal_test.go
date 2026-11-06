package sigil

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAESKeyWrapRFC3394(t *testing.T) {
	tests := []struct{ kek, key, wrapped string }{
		{ // 4.1
			"000102030405060708090A0B0C0D0E0F",
			"00112233445566778899AABBCCDDEEFF",
			"1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
		},
		{ // 4.6
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			"28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
		},
	}
	for _, tt := range tests {
		kek, key, want := unhex(t, tt.kek), unhex(t, tt.key), unhex(t, tt.wrapped)
		got, err := wrapKey(kek, key)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("wrap = %X, %v; want %X", got, err, want)
		}
		back, err := unwrapKey(kek, got)
		if err != nil || !bytes.Equal(back, key) {
			t.Fatalf("unwrap = %X, %v", back, err)
		}
		got[3] ^= 1
		if _, err := unwrapKey(kek, got); err == nil {
			t.Fatal("unwrap accepted a corrupted key")
		}
	}
}

// RFC 7518 Appendix C.
func TestECDHESRFC7518(t *testing.T) {
	bob, err := ParseJWK([]byte(`{"kty":"EC","crv":"P-256",
		"x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
		"y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
		"d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}`))
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]any{
		"alg": "ECDH-ES", "enc": "A128GCM", "apu": "QWxpY2U", "apv": "Qm9i",
		"epk": map[string]any{
			"kty": "EC", "crv": "P-256",
			"x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
			"y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
		},
	}
	cek, err := decryptKey(bob, ECDHES, A128GCM, header, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := b64encode(cek); got != "VqqN6vgjbSBcIijNcacQGg" {
		t.Fatalf("derived key = %s", got)
	}
}

// RFC 7516 Appendix A.3: A128KW with A128CBC-HS256.
func TestJWERFC7516A3(t *testing.T) {
	key, err := ParseJWK([]byte(`{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}`))
	if err != nil {
		t.Fatal(err)
	}
	protected := "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0"
	var segments [][]byte
	for _, s := range []string{
		"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
		"AxY8DCtDaGlsbGljb3RoZQ",
		"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
		"U0m_YmjN04DJvceFICbCVQ",
	} {
		segments = append(segments, mustDecode(t, s))
	}
	var header map[string]any
	if err := json.Unmarshal(mustDecode(t, protected), &header); err != nil {
		t.Fatal(err)
	}
	plaintext, err := decryptWith(key, A128KW, A128CBCHS256, header, segments, []byte(protected))
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "Live long and prosper." {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b64decode(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
