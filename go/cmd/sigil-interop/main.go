// Command sigil-interop generates and checks the cross-language interop tokens
// described in SPEC.md.
//
//	sigil-interop [-testdata dir] gen <out.json>
//	sigil-interop [-testdata dir] check <in.json>
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"

	sigil "github.com/hostfog/sigil/go"
)

type interopCase struct {
	Kind  string `json:"kind"`
	Alg   string `json:"alg"`
	Enc   string `json:"enc,omitempty"`
	Key   string `json:"key"`
	Token string `json:"token,omitempty"`
}

type fixtures struct {
	claims map[string]any
	cases  []interopCase
	keys   *sigil.KeySet
}

func main() {
	testdata := flag.String("testdata", "../testdata", "path to the shared testdata directory")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: sigil-interop [-testdata dir] gen|check <file>")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(2)
	}

	fx, err := load(*testdata)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch flag.Arg(0) {
	case "gen":
		err = gen(fx, flag.Arg(1))
	case "check":
		err = check(fx, flag.Arg(1))
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func load(dir string) (*fixtures, error) {
	data, err := os.ReadFile(filepath.Join(dir, "interop.json"))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Claims map[string]any `json:"claims"`
		Cases  []interopCase  `json:"cases"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("interop.json: %w", err)
	}
	jwks, err := os.ReadFile(filepath.Join(dir, "keys.json"))
	if err != nil {
		return nil, err
	}
	keys, err := sigil.ParseJWKS(jwks)
	if err != nil {
		return nil, fmt.Errorf("keys.json: %w", err)
	}
	return &fixtures{claims: doc.Claims, cases: doc.Cases, keys: keys}, nil
}

func gen(fx *fixtures, out string) error {
	results := make([]interopCase, 0, len(fx.cases))
	for _, c := range fx.cases {
		key := fx.keys.Get(c.Key)
		if key == nil {
			return fmt.Errorf("unknown key %q", c.Key)
		}
		var err error
		if c.Kind == "jws" {
			c.Token, err = sigil.Sign(fx.claims, key, sigil.WithAlgorithm(c.Alg))
		} else {
			if pub := key.Public(); pub != nil {
				key = pub
			}
			c.Token, err = sigil.Encrypt(fx.claims, key, sigil.WithKeyAlgorithm(c.Alg), sigil.WithEncryption(c.Enc))
		}
		if err != nil {
			return fmt.Errorf("%s %s %s: %w", c.Kind, c.Alg, c.Enc, err)
		}
		results = append(results, c)
	}
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, append(data, '\n'), 0o644)
}

func check(fx *fixtures, in string) error {
	data, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var cases []interopCase
	if err := json.Unmarshal(data, &cases); err != nil {
		return fmt.Errorf("%s: %w", in, err)
	}
	want := normalize(fx.claims)
	failed := 0
	for _, c := range cases {
		if err := checkCase(fx, c, want); err != nil {
			failed++
			fmt.Printf("FAIL %s %s %s (%s): %v\n", c.Kind, c.Alg, c.Enc, c.Key, err)
			continue
		}
		fmt.Printf("ok   %s %s %s (%s)\n", c.Kind, c.Alg, c.Enc, c.Key)
	}
	fmt.Printf("%d/%d passed\n", len(cases)-failed, len(cases))
	if failed > 0 || len(cases) == 0 {
		return fmt.Errorf("%d cases failed", failed)
	}
	return nil
}

func checkCase(fx *fixtures, c interopCase, want any) error {
	key := fx.keys.Get(c.Key)
	if key == nil {
		return fmt.Errorf("unknown key %q", c.Key)
	}
	opts := []sigil.VerifyOption{
		sigil.Algorithms(c.Alg),
		sigil.Issuer("sigil"),
		sigil.Audience("all"),
		sigil.Now(time.Unix(1800000000, 0)),
	}
	var tok *sigil.Token
	var err error
	if c.Kind == "jws" {
		tok, err = sigil.Verify(c.Token, key, opts...)
	} else {
		tok, err = sigil.Decrypt(c.Token, key, opts...)
		if err == nil && tok.Header["enc"] != c.Enc {
			return fmt.Errorf("enc is %v, want %s", tok.Header["enc"], c.Enc)
		}
	}
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(normalize(tok.Claims), want) {
		return fmt.Errorf("claims differ")
	}
	return nil
}

// normalize round-trips v through JSON so numbers compare by value.
func normalize(v any) any {
	b, _ := json.Marshal(v)
	var out any
	json.Unmarshal(b, &out)
	return out
}
