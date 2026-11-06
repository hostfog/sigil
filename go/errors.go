package sigil

// Error is the error type returned by every Sigil operation.
// Code is one of the stable codes from the spec; Claim names the
// offending claim for invalid_claim errors.
type Error struct {
	Code  string
	Claim string
	msg   string
}

// Sentinel errors for use with errors.Is. They match any *Error with the same Code.
var (
	ErrMalformed        = &Error{Code: "malformed", msg: "malformed token"}
	ErrUnsupportedAlg   = &Error{Code: "unsupported_alg", msg: "unsupported algorithm"}
	ErrInvalidKey       = &Error{Code: "invalid_key", msg: "invalid key"}
	ErrKeyNotFound      = &Error{Code: "key_not_found", msg: "key not found"}
	ErrInvalidSignature = &Error{Code: "invalid_signature", msg: "invalid signature"}
	ErrExpired          = &Error{Code: "expired", msg: "token expired"}
	ErrNotYetValid      = &Error{Code: "not_yet_valid", msg: "token not yet valid"}
	ErrInvalidClaim     = &Error{Code: "invalid_claim", msg: "invalid claim"}
)

func (e *Error) Error() string {
	return "sigil: " + e.msg
}

// Is reports whether target is an *Error with the same code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

func fail(kind *Error, msg string) *Error {
	return &Error{Code: kind.Code, msg: msg}
}

func claimError(kind *Error, claim, msg string) *Error {
	return &Error{Code: kind.Code, Claim: claim, msg: claim + ": " + msg}
}
