package signers

import "fmt"

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

func (a *AuthenticationError) Error() string {
	return a.Message
}

func Errorf(status int, errtype ErrorType, format string, args ...interface{}) *AuthenticationError {
	return &AuthenticationError{
		Message:    fmt.Sprintf(format, args...),
		HttpStatus: status,
		ErrorType:  errtype,
	}
}

func GetErrorType(e error) ErrorType {
	if ae, ok := e.(*AuthenticationError); ok {
		return ae.ErrorType
	} else {
		return ErrorTypeUnknown
	}
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
