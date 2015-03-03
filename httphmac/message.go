// Package httphmac provides functions for signing HTTP requests, implementing
// the HTTP HMAC Spec. https://github.com/acquia/http-hmac-spec
package httphmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// A Message represents the parts of the HTTP request used in the generation of
// the HMAC signature.
type Message struct {
	// Method specifies the HTTP method (GET, POST, PUT, etc.).
	Method string

	// BodyHash specifies the MD5 hash of the raw body of the HTTP request.
	BodyHash string

	// ContentType specifies the value of the "Content-type" header.
	ContentType string

	// Date specifies the value of the "Date" header or a custom header, e.g.
	// "x-acquia-timestamp".
	Date string

	// CustomHeaders specifies a collection of custom headers used in
	// generating the signature.
	CustomHeaders *Headers

	// Resource specifies the URI being requested (for server requests) or the URL
	// to access (for client requests).
	Resource *url.URL
}

// NewMessage returns a new Message given a HTTP request, and an array of
// custom headers used in the HMAC signature generation.
func NewMessage(r *http.Request, headers ...[]string) *Message {

	h := NewHeaders()
	if len(headers) > 0 {
		for _, header := range headers[0] {
			h.Set(header, r.Header.Get(header))
		}
	}

	var body []byte = []byte{}
	if r.Body != nil {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil
		}
		r.Body.Close()
		r.Body = ioutil.NopCloser(bytes.NewReader(body))
	}

	return &Message{
		r.Method,
		HashData(body),
		r.Header.Get("Content-Type"),
		r.Header.Get("Date"),
		h,
		r.URL,
	}
}

// Bytes returns a slice of the contents of the Message used in the HMAC
// signature generation.
func (m *Message) Bytes() []byte {
	var b bytes.Buffer

	b.WriteString(strings.ToUpper(m.Method))
	b.WriteString("\n")

	b.WriteString(m.BodyHash)
	b.WriteString("\n")

	b.WriteString(strings.ToLower(m.ContentType))
	b.WriteString("\n")

	b.WriteString(m.Date)
	b.WriteString("\n")

	b.Write(m.CustomHeaders.Bytes())

	b.WriteString(m.Resource.RequestURI())

	return b.Bytes()
}

// Sign returns the HMAC signature.
func (m *Message) Sign(digest func() hash.Hash, secret string) string {
	h := hmac.New(digest, []byte(secret))
	b := m.Bytes()
	h.Write(b)
	hsm := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(hsm)
}

// HashData returns an MD5 hash of the request body, given the body itself.
func HashData(body []byte) string {
	h := md5.New()
	h.Write(body)

	return hex.EncodeToString(h.Sum(nil))
}

// A Headers represents the custom headers used in the HMAC signature generation.
type Headers struct {
	// Values specifies the custom headers used in the HMAC signature generation.
	values map[string]string
}

// NewHeaders returns a new Headers.
func NewHeaders() *Headers {
	return &Headers{
		values: make(map[string]string),
	}
}

// Set sets the value of a custom header used in the HMAC signature generation.
func (h *Headers) Set(header, value string) *Headers {
	h.values[strings.ToLower(header)] = value
	return h
}

// Bytes returns a slice of the contents of the custom headers used in the HMAC
// signature generation.
func (h *Headers) Bytes() []byte {
	var b bytes.Buffer

	for k, v := range h.values {
		b.WriteString(k + ": " + v)
		b.WriteString("\n")
	}

	if b.Len() == 0 {
		b.WriteString("\n")
	}

	return b.Bytes()
}
