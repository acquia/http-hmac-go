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
	Sign(req *http.Request, authHeaders map[string]string, secret string) (string, *AuthenticationError)
	GetIdentificationRegex() *regexp.Regexp
	HashBody(req *http.Request) (string, *AuthenticationError)
	GetResponseSigner() ResponseSigner
	ParseAuthHeaders(req *http.Request) map[string]string
}

type ResponseSigner interface {
	SignResponse(req *http.Request, rw *SignableResponseWriter, secret string) (string, *AuthenticationError)
	SignResponseDirect(req *http.Request, rw *SignableResponseWriter, secret string) *AuthenticationError
}

func NormalizedHeaderName(key string) string {
	return strings.ToLower(key)
}
