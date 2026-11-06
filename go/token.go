package sigil

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"strings"
)

// Token is a verified, decrypted or decoded token. Numeric claims are json.Number.
type Token struct {
	Header map[string]any
	Claims map[string]any
}

// Bind decodes the claims into v, which is typically a pointer to a struct.
func (t *Token) Bind(v any) error {
	b, err := json.Marshal(t.Claims)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Decode parses a JWS without verifying it.
func Decode(token string) (*Token, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fail(ErrMalformed, "JWS must have 3 parts")
	}
	header, err := parseHeader(parts[0])
	if err != nil {
		return nil, err
	}
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, err
	}
	claims, err := parseObject(payload)
	if err != nil {
		return nil, err
	}
	return &Token{Header: header, Claims: claims}, nil
}

func decodeSegment(s string) ([]byte, error) {
	b, err := b64decode(s)
	if err != nil {
		return nil, fail(ErrMalformed, "invalid base64url segment")
	}
	return b, nil
}

func parseHeader(segment string) (map[string]any, error) {
	b, err := decodeSegment(segment)
	if err != nil {
		return nil, err
	}
	h, err := parseObject(b)
	if err != nil {
		return nil, fail(ErrMalformed, "header is not a JSON object")
	}
	return h, nil
}

// parseObject decodes a single JSON object, keeping numbers as json.Number.
func parseObject(b []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, fail(ErrMalformed, "payload is not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fail(ErrMalformed, "trailing data after JSON object")
	}
	return m, nil
}

func marshalClaims(claims any) ([]byte, error) {
	b, err := json.Marshal(claims)
	if err != nil || len(b) == 0 || b[0] != '{' {
		return nil, fail(ErrMalformed, "claims must encode to a JSON object")
	}
	return b, nil
}

// checkHeader validates alg, crit and zip and returns alg and kid.
func checkHeader(h map[string]any, known []string, keys KeySource, cfg *verifyConfig) (alg, kid string, err error) {
	alg, ok := h["alg"].(string)
	if !ok {
		return "", "", fail(ErrMalformed, "missing alg header")
	}
	if !slices.Contains(known, alg) {
		return "", "", fail(ErrUnsupportedAlg, "unsupported algorithm")
	}
	allowed := keys.allows(alg)
	if len(cfg.algorithms) > 0 {
		allowed = slices.Contains(cfg.algorithms, alg)
	}
	if !allowed {
		return "", "", fail(ErrUnsupportedAlg, "algorithm "+alg+" is not allowed")
	}
	if _, ok := h["crit"]; ok {
		return "", "", fail(ErrUnsupportedAlg, "crit header is not supported")
	}
	if _, ok := h["zip"]; ok {
		return "", "", fail(ErrUnsupportedAlg, "zip header is not supported")
	}
	if v, ok := h["kid"]; ok {
		if kid, ok = v.(string); !ok {
			return "", "", fail(ErrMalformed, "kid header must be a string")
		}
	}
	return alg, kid, nil
}
