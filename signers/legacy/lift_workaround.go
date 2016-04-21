package legacy

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/acquia/http-hmac-go/signers"
)

type LiftSigner struct {
	*signers.Digester
	*signers.Identifiable
}

func NewLiftSigner() (*LiftSigner, *signers.AuthenticationError) {
	re, err := regexp.Compile("(?i)^\\s*HMAC\\s*[^:]+\\s*:\\s*[0-9a-zA-Z\\+/=]+\\s*$")
	if err != nil {
		return nil, signers.Errorf(500, signers.ErrorTypeInternalError, "Could not compile regular expression for identifier: %s", err.Error())
	}
	return &LiftSigner{
		Digester: &signers.Digester{
			Digest: sha1.New,
		},
		Identifiable: &signers.Identifiable{
			IdRegex: re,
		},
	}, nil
}

func (v *LiftSigner) HashBody(req *http.Request) (string, *signers.AuthenticationError) {
	h := md5.New()
	data, err := signers.ReadBody(req)
	if err != nil {
		return "", signers.Errorf(500, signers.ErrorTypeInternalError, "Failed to read request body: %s", err.Error())
	}
	h.Write(data)

	return hex.EncodeToString(h.Sum(nil)), nil
}

// See guidelines at https://docs.acquia.com/lift/omni/api/hmac
func (v *LiftSigner) CreateSignable(req *http.Request, authHeaders map[string]string) []byte {
	var b bytes.Buffer

	// Add the HTTP verb for the request (for example, GET or POST) in capital
	// letters, followed by a single newline (U+000A).
	b.WriteString(strings.ToUpper(req.Method))
	b.WriteString("\n")

	// Convert specific header names to lowercase. Currently supported headers are:
	// accept, host (domain name only, no protocol), user-agent
	// 1. Sort the headers lexicographically by header name.
	//
	// 2. Trim header values by removing any whitespace.
	// Combine lowercase header names and header values using a single colon as
	// the separator. Do not include whitespace characters around the separator.
	//
	// 3. Combine the specific headers using a single newline character (U+000A) as
	// the separator and append them to the canonical representation, followed by
	// a single newline character (U+000A).
	acceptValue := req.Header.Get("Accept")
	if len(acceptValue) > 0 {
		b.WriteString("accept:" + acceptValue)
		b.WriteString("\n")
	}

	hostValue := req.Host
	if len(hostValue) > 0 {
		b.WriteString("host:" + hostValue)
		b.WriteString("\n")
	}

	userAgentValue := req.UserAgent()
	if len(userAgentValue) > 0 {
		b.WriteString("user-agent:" + userAgentValue)
		b.WriteString("\n")
	}

	// Append the request URI (the part of this request's URL from the protocol
	// name up to the query string) to the canonical representation.
	// @todo Documentation tells us including hostname, in practice its without
	// the hostname and only includes the path.
	b.WriteString(req.URL.Path)

	// Add sorted parameters
	sortedFragment := v.getSortedFragment(req.URL)
	if len(sortedFragment) > 0 {
		b.WriteString("?")
		b.WriteString(sortedFragment)
	}

	ret := b.Bytes()
	signers.Logf("Signable:\n%s", string(ret))
	return ret
}

// Sort all parameters by parameter name, and then join them using a single
// ampersand as the separator.
func (v *LiftSigner) getSortedFragment(url *url.URL) string {
	values := url.Query()
	var sortedValues []string
	var keys []string
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sortedValues = append(sortedValues, k+"="+values.Get(k))
	}
	sortedFragment := strings.Join(sortedValues, "&")
	return sortedFragment
}

func (v *LiftSigner) Sign(req *http.Request, authHeaders map[string]string, secret string) (string, *signers.AuthenticationError) {
	h := hmac.New(v.Digest, []byte(secret))
	b := v.CreateSignable(req, authHeaders)
	h.Write(b)
	hsm := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(hsm), nil
}

func (v *LiftSigner) Check(req *http.Request, secret string) *signers.AuthenticationError {
	sig, err := v.Sign(req, map[string]string{}, secret)
	if err != nil {
		return err
	}
	header := req.Header.Get("Authorization")
	parts := strings.SplitN(header, ":", 2)
	if len(parts) < 2 {
		return signers.Errorf(403, signers.ErrorTypeInvalidAuthHeader, "Signature missing from authorization header.")
	}
	if sig != parts[1] {
		return signers.Errorf(403, signers.ErrorTypeSignatureMismatch, "Signature does not match expected signature.")
	}
	return nil
}

func (v *LiftSigner) SignDirect(req *http.Request, authHeaders map[string]string, secret string) *signers.AuthenticationError {
	sig, err := v.Sign(req, map[string]string{}, secret)
	if err != nil {
		return err
	}
	ah, err := v.GenerateAuthorization(req, authHeaders, sig)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", ah)
	return nil
}

func (v *LiftSigner) GenerateAuthorization(req *http.Request, authHeaders map[string]string, signature string) (string, *signers.AuthenticationError) {
	if acc, ok := authHeaders["id"]; !ok {
		return "", signers.Errorf(500, signers.ErrorTypeInternalError, "Missing access key for signature.")
	} else {
		return fmt.Sprintf("HMAC %s:%s", acc, signature), nil
	}
}

func (v *LiftSigner) GetIdentificationRegex() *regexp.Regexp {
	return v.IdRegex
}

func (v *LiftSigner) GetResponseSigner() signers.ResponseSigner {
	return nil
}

func (v *LiftSigner) Version() int {
	return 1
}
