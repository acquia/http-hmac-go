package signers

import (
	"hash"
	"net/http"
	"regexp"
	"strings"
)

type Digester struct {
	Digest func() hash.Hash
}

type Identifiable struct {
	IdRegex *regexp.Regexp
}

type Signer interface {
	// Generates a signature according to a request. Does not alter the request.
	// Fails if headers necessary for signing are missing.
	// Does not alter the contents of the request, but req.Body's address may change.
	Sign(req *http.Request, authHeaders map[string]string, secret string) (string, *AuthenticationError)

	// Returns a regular expression that matches the authorization header for the version of the signature
	// that the signer represents, but not any other version.
	GetIdentificationRegex() *regexp.Regexp

	// Hashes the body of a request according to the signature specifications.
	// Does not alter the contents of the request, but req.Body's address may change.
	HashBody(req *http.Request) (string, *AuthenticationError)

	// Returns a response signer for this type of signature if one exists. May return nil if no specification
	// exists for response signing.
	GetResponseSigner() ResponseSigner

	// Reads the authorization headers from the Authorization field of a request and returns them as a map.
	// Does not alter the request.
	ParseAuthHeaders(req *http.Request) map[string]string

	// Verifies whether or not a request bears a valid Authorization header.
	// May also check other required headers and a return an error if they are missing.
	// In short, Check() verifies whether a signed request is valid, up to specifications and bears the expected signature.
	Check(req *http.Request, secret string) *AuthenticationError

	// Directly signs the request, generating the appropriate headers if necessary.
	SignDirect(req *http.Request, authHeaders map[string]string, secret string) *AuthenticationError

	// Generates the Authorization header's value for a request using the authorization headers and a signature.
	// Does not alter the request.
	// Does not alter the contents of the request, but req.Body's address may change.
	GenerateAuthorization(req *http.Request, authHeaders map[string]string, signature string) (string, *AuthenticationError)

	// Returns a version number, or 0 if unknown.
	Version() int
}

type ResponseSigner interface {
	SignResponse(req *http.Request, rw *SignableResponseWriter, secret string) (string, *AuthenticationError)
	SignResponseDirect(req *http.Request, rw *SignableResponseWriter, secret string) *AuthenticationError
	Check(req *http.Request, resp *http.Response, secret string) *AuthenticationError
	SetTrailer(rw http.ResponseWriter)
}

func NormalizedHeaderName(key string) string {
	return strings.ToLower(key)
}
