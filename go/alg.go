package sigil

import (
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// JWS algorithms.
const (
	HS256 = "HS256"
	HS384 = "HS384"
	HS512 = "HS512"
	RS256 = "RS256"
	RS384 = "RS384"
	RS512 = "RS512"
	PS256 = "PS256"
	PS384 = "PS384"
	PS512 = "PS512"
	ES256 = "ES256"
	ES384 = "ES384"
	ES512 = "ES512"
	EdDSA = "EdDSA"
)

// JWE key management algorithms.
const (
	Dir          = "dir"
	A128KW       = "A128KW"
	A192KW       = "A192KW"
	A256KW       = "A256KW"
	RSAOAEP      = "RSA-OAEP"
	RSAOAEP256   = "RSA-OAEP-256"
	ECDHES       = "ECDH-ES"
	ECDHESA128KW = "ECDH-ES+A128KW"
	ECDHESA192KW = "ECDH-ES+A192KW"
	ECDHESA256KW = "ECDH-ES+A256KW"
)

// JWE content encryption algorithms.
const (
	A128GCM      = "A128GCM"
	A192GCM      = "A192GCM"
	A256GCM      = "A256GCM"
	A128CBCHS256 = "A128CBC-HS256"
	A192CBCHS384 = "A192CBC-HS384"
	A256CBCHS512 = "A256CBC-HS512"
)

var jwsAlgs = []string{HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA}

var jweAlgs = []string{Dir, A128KW, A192KW, A256KW, RSAOAEP, RSAOAEP256, ECDHES, ECDHESA128KW, ECDHESA192KW, ECDHESA256KW}

var hashes = map[string]crypto.Hash{
	HS256: crypto.SHA256, HS384: crypto.SHA384, HS512: crypto.SHA512,
	RS256: crypto.SHA256, RS384: crypto.SHA384, RS512: crypto.SHA512,
	PS256: crypto.SHA256, PS384: crypto.SHA384, PS512: crypto.SHA512,
	ES256: crypto.SHA256, ES384: crypto.SHA384, ES512: crypto.SHA512,
}

// wrapSizes holds the key-encryption key size in bytes for the AES key wrap algorithms.
var wrapSizes = map[string]int{
	A128KW: 16, A192KW: 24, A256KW: 32,
	ECDHESA128KW: 16, ECDHESA192KW: 24, ECDHESA256KW: 32,
}

// encSizes holds the content encryption key size in bytes for each enc.
var encSizes = map[string]int{
	A128GCM: 16, A192GCM: 24, A256GCM: 32,
	A128CBCHS256: 32, A192CBCHS384: 48, A256CBCHS512: 64,
}

var ecdsaCurves = map[string]string{ES256: "P-256", ES384: "P-384", ES512: "P-521"}
