package signers

import "fmt"

// AuthenticationError no longer implements the error interface because:
// - go is dumb
// - the people behind go are illogical bastards
// - and i'm also dumb for repeatedly falling into the trap the two aforementioned things lay me
// No, it won't ever implement error. Not until there is a unified way to check for nils in Go.
// Trust me.
// It's better this way.
// One day you'll thank me for it.
// You'll never know what it's like to fall into the trap set by this four times and waste 32 perfectly
// fine manhours on it.
type AuthenticationError struct {
	Message    string
	HttpStatus int
	ErrorType  ErrorType
}

type ErrorType int

const (
	ErrorTypeNoError ErrorType = iota
	ErrorTypeUnknown
	ErrorTypeUnknownSignatureType
	ErrorTypeTimestampRangeError
	ErrorTypeMissingRequiredHeader
	ErrorTypeInvalidRequiredHeader
	ErrorTypeInvalidAuthHeader
	ErrorTypeOutdatedKeypair
	ErrorTypeInternalError
	ErrorTypeSignatureMismatch
)

func Errorf(status int, errtype ErrorType, format string, args ...interface{}) *AuthenticationError {
	return &AuthenticationError{
		Message:    fmt.Sprintf(format, args...),
		HttpStatus: status,
		ErrorType:  errtype,
	}
}

// Here you go.
func (a *AuthenticationError) ToError() error {
	return fmt.Errorf(fmt.Sprintf("(%d), %s: %s", a.HttpStatus, GetErrorTypeText(a.ErrorType), a.Message))
}

func GetErrorTypeText(e ErrorType) string {
	switch e {
	case ErrorTypeNoError:
		return "no error"
	case ErrorTypeUnknownSignatureType:
		return "unknown signature type"
	case ErrorTypeTimestampRangeError:
		return "timestamp range error"
	case ErrorTypeMissingRequiredHeader:
		return "missing required header"
	case ErrorTypeInvalidRequiredHeader:
		return "invalid required header value"
	case ErrorTypeInvalidAuthHeader:
		return "invalid authorization header"
	case ErrorTypeOutdatedKeypair:
		return "keypair version error"
	case ErrorTypeInternalError:
		return "internal authorization error"
	case ErrorTypeUnknown:
		fallthrough
	default:
		return "unknown error"
	}
}
