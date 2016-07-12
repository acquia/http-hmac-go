package v2

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/acquia/http-hmac-go/signers"
	"hash"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type V2Signer struct {
	*signers.Digester
	*signers.Identifiable
	respSigner *V2ResponseSigner
}

func EscapeProper(s string) string {
	return strings.Replace(url.QueryEscape(s), "+", "%20", -1)
}

func ParseAuthHeaders(req *http.Request) map[string]string {
	auth := req.Header.Get("Authorization")
	ret := map[string]string{}
	if len(auth) == 0 {
		return ret
	}
	s1 := strings.SplitN(auth, " ", 2)
	s2 := strings.Split(s1[1], ",")
	for len(s2) > 0 {
		var vardef string
		vardef, s2 = strings.TrimLeft(s2[0], " \t\n"), s2[1:]
		for !strings.HasSuffix(strings.TrimRight(vardef, " \t\n"), "\"") {
			if len(s2) > 0 {
				vardef, s2 = fmt.Sprintf("%s,%s", vardef, s2[0]), s2[1:]
			} else {
				return map[string]string{}
			}
		}
		vardef = strings.TrimRight(vardef, " \t\n")
		parts := strings.SplitN(vardef, "=", 2)
		k := strings.Trim(parts[0], " \t\n")
		qu := strings.Trim(parts[1], " \t\n\"")
		if k != "signature" { // hack
			qu, _ = url.QueryUnescape(qu)
		}
		ret[k] = qu
	}
	return ret
}

func (v *V2Signer) ParseAuthHeaders(req *http.Request) map[string]string {
	return ParseAuthHeaders(req)
}

func NewV2Signer(digest func() hash.Hash) (*V2Signer, *signers.AuthenticationError) {
	re, err := regexp.Compile("(?i)^\\s*acquia-http-hmac.*?version=\"2\\.0\".*?$")
	if err != nil {
		return nil, signers.Errorf(500, signers.ErrorTypeInternalError, "Could not compile regular expression for identifier: %s", err.Error())
	}
	return &V2Signer{
		Digester: &signers.Digester{
			Digest: digest,
		},
		Identifiable: &signers.Identifiable{
			IdRegex: re,
		},
		respSigner: NewV2ResponseSigner(digest),
	}, nil
}

func (v *V2Signer) stringAuthHeaders(authHeaders map[string]string) string {
	return fmt.Sprintf("id=%s&nonce=%s&realm=%s&version=2.0", EscapeProper(authHeaders["id"]), EscapeProper(authHeaders["nonce"]), EscapeProper(authHeaders["realm"]))
}

func (v *V2Signer) HashBody(req *http.Request) (string, *signers.AuthenticationError) {
	data, err := signers.ReadBody(req)
	if err != nil {
		return "", signers.Errorf(500, signers.ErrorTypeInternalError, "Failed to read request body: %s", err.Error())
	}
	return v.HashBytes(data), nil
}

func (v *V2Signer) HashBytes(b []byte) string {
	h := sha256.New()
	h.Write(b)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (v *V2Signer) CreateSignable(req *http.Request, authHeaders map[string]string, bodyhash string) []byte {
	var b bytes.Buffer

	// The uppercase HTTP request method e.g. "GET", "POST".
	method := strings.ToUpper(req.Method)
	b.WriteString(method)
	b.WriteString("\n")

	// The (lowercase) hostname, matching the HTTP "Host" request header field
	// (including any port number).
	b.WriteString(req.Host)
	b.WriteString("\n")

	// The HTTP request path with leading slash, e.g. /resource/11
	b.WriteString(signers.Path(req.URL))
	b.WriteString("\n")

	// Any query parameters or empty string. This should be the exact string sent
	// by the client, including urlencoding.
	b.WriteString(req.URL.RawQuery)
	b.WriteString("\n")

	// normalized parameters similar to section 9.1.1 of OAuth 1.0a. The
	// parameters are the id, nonce, realm, and version from the Authorization
	// header. Parameters are sorted by name and separated by '&' with name and
	// value separated by =, percent encoded (urlencoded).
	b.WriteString(v.stringAuthHeaders(authHeaders))
	b.WriteString("\n")

	if hdr, ok := authHeaders["headers"]; ok {
		if hdr != "" {
			hdrs := strings.Split(hdr, ";")
			sort.Strings(hdrs)
			for _, key := range hdrs {
				b.WriteString(signers.NormalizedHeaderName(key))
				b.WriteString(":")
				b.WriteString(req.Header.Get(key))
				b.WriteString("\n")
			}
		}
	}

	// The value of the X-Authorization-Timestamp header.
	b.WriteString(req.Header.Get("X-Authorization-Timestamp"))

	if bodyhash != "" && req.ContentLength > 0 {
		b.WriteString("\n")
		// The lowercase value of the "Content-type" header (or empty string if
		// absent). Omit if Content-Length is 0.
		b.WriteString(strings.ToLower(req.Header.Get("Content-Type")))
		b.WriteString("\n")
		// The base64 encoded SHA-256 digest of the raw body of the HTTP request,
		// for POST, PUT, PATCH, DELETE or other requests that may have a body.
		// Omit if Content-Length is 0. This should be identical to the string sent
		// as the X-Authorization-Content-SHA256 header.
		b.WriteString(bodyhash)
	}

	ret := b.Bytes()
	signers.Logf("Signable:\n%s", string(ret))
	return ret
}

func (v *V2Signer) ahKeyCheck(authHeaders map[string]string, key string) *signers.AuthenticationError {
	if _, ok := authHeaders[key]; !ok {
		return signers.Errorf(403, signers.ErrorTypeInvalidAuthHeader, "%s is required for authentication headers", key)
	}
	return nil
}

func (v *V2Signer) ahKeyCheckBulk(authHeaders map[string]string, keys []string) *signers.AuthenticationError {
	for _, key := range keys {
		if err := v.ahKeyCheck(authHeaders, key); err != nil {
			return err
		}
	}
	return nil
}

func (v *V2Signer) readCustomHeaders(authHeaders map[string]string) []string {
	if d, ok := authHeaders["headers"]; ok {
		return strings.Split(d, ";")
	}
	return []string{}
}

func (v *V2Signer) Sign(req *http.Request, authHeaders map[string]string, secret string) (string, *signers.AuthenticationError) {
	if err := v.ahKeyCheckBulk(authHeaders, []string{"id", "nonce", "realm"}); err != nil {
		return "", err
	}
	if req.Header.Get("X-Authorization-Timestamp") == "" {
		return "", signers.Errorf(403, signers.ErrorTypeMissingRequiredHeader, "Missing required header X-Authorization-Timestamp.")
	}
	var bodyhash string = ""
	body, err := signers.ReadBody(req)
	if err != nil {
		return "", signers.Errorf(500, signers.ErrorTypeInternalError, "Failed to read request body: %s", err.Error())
	}
	if len(body) > 0 {
		bodyhash = v.HashBytes(body)
	}

	decoded, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", signers.Errorf(403, signers.ErrorTypeOutdatedKeypair, "The provided secret key is not in a valid base64 format: %s", err.Error())
	}
	h := hmac.New(v.Digest, decoded)
	b := v.CreateSignable(req, authHeaders, bodyhash)
	h.Write(b)
	hsm := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(hsm), nil
}

func (v *V2Signer) Check(req *http.Request, secret string) *signers.AuthenticationError {
	authHeaders := ParseAuthHeaders(req)
	if req.Header.Get("X-Authorization-Timestamp") == "" {
		return signers.Errorf(403, signers.ErrorTypeMissingRequiredHeader, "Missing required header X-Authorization-Timestamp.")
	}
	body, err := signers.ReadBody(req)
	if err != nil {
		return signers.Errorf(500, signers.ErrorTypeInternalError, "Failed to read request body: %s", err.Error())
	}
	if len(body) > 0 {
		if req.Header.Get("X-Authorization-Content-Sha256") == "" {
			return signers.Errorf(403, signers.ErrorTypeMissingRequiredHeader, "Missing required header X-Authorization-Content-SHA256.")
		}
		if v.HashBytes(body) != req.Header.Get("X-Authorization-Content-Sha256") {
			return signers.Errorf(403, signers.ErrorTypeInvalidRequiredHeader, "Content mismatch - X-Authorization-Content-SHA256 must match the SHA hash of the request body.")
		}
	}
	timestamp, err := strconv.ParseInt(req.Header.Get("X-Authorization-Timestamp"), 10, 64)
	if err != nil {
		return signers.Errorf(403, signers.ErrorTypeInvalidRequiredHeader, "Timestamp parse error: %s", err.Error())
	}
	if timestamp > signers.Now().Unix()+900 {
		return signers.Errorf(403, signers.ErrorTypeTimestampRangeError, "Timestamp given in X-Authorization-Timestamp (%d) was too far in the future.", timestamp)
	}
	if timestamp < signers.Now().Unix()-900 {
		return signers.Errorf(403, signers.ErrorTypeTimestampRangeError, "Timestamp given in X-Authorization-Timestamp (%d) was too far in the past.", timestamp)
	}

	sig, serr := v.Sign(req, authHeaders, secret)
	if serr != nil {
		return serr
	}
	got := authHeaders["signature"]
	if got == "" {
		return signers.Errorf(403, signers.ErrorTypeInvalidAuthHeader, "Signature missing from authorization header.")
	}
	if sig != got {
		return signers.Errorf(403, signers.ErrorTypeSignatureMismatch, "Signature does not match expected signature.")
	}
	return nil
}

func (v *V2Signer) SignDirect(req *http.Request, authHeaders map[string]string, secret string) *signers.AuthenticationError {
	if req.Header.Get("X-Authorization-Timestamp") == "" {
		req.Header.Set("X-Authorization-Timestamp", strconv.Itoa(int(signers.Now().Unix())))
	}
	body, err := signers.ReadBody(req)
	if err != nil {
		return signers.Errorf(500, signers.ErrorTypeInternalError, "Failed to read request body: %s", err.Error())
	}
	if len(body) > 0 && req.Header.Get("X-Authorization-Content-Sha256") == "" {
		req.Header.Set("X-Authorization-Content-Sha256", v.HashBytes(body))
	}
	sig, serr := v.Sign(req, authHeaders, secret)
	if serr != nil {
		return serr
	}
	ah, serr := v.GenerateAuthorization(req, authHeaders, sig)
	if serr != nil {
		return serr
	}

	req.Header.Set("Authorization", ah)
	return nil
}

func (v *V2Signer) GenerateAuthorization(req *http.Request, authHeaders map[string]string, signature string) (string, *signers.AuthenticationError) {
	if _, ok := authHeaders["id"]; !ok {
		return "", signers.Errorf(500, signers.ErrorTypeInternalError, "Missing access key for signature.")
	}
	if _, ok := authHeaders["nonce"]; !ok {
		return "", signers.Errorf(500, signers.ErrorTypeInternalError, "Missing nonce for signature.")
	}
	if _, ok := authHeaders["realm"]; !ok {
		return "", signers.Errorf(500, signers.ErrorTypeInternalError, "Missing realm for signature.")
	}
	if _, ok := authHeaders["version"]; !ok {
		authHeaders["version"] = "2.0"
	}
	authHeaders["signature"] = signature
	args := ""
	sorted := []string{}
	for k, _ := range authHeaders {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		if args != "" {
			args += ","
		}
		v := authHeaders[k]
		if k != "signature" { // hack
			v = EscapeProper(v)
		}
		args += fmt.Sprintf("%s=\"%s\"", k, v)
	}

	return fmt.Sprintf("acquia-http-hmac %s", args), nil
}

func (v *V2Signer) GetIdentificationRegex() *regexp.Regexp {
	return v.IdRegex
}

func (v *V2Signer) GetResponseSigner() signers.ResponseSigner {
	return v.respSigner
}

func (v *V2Signer) Version() int {
	return 2
}
