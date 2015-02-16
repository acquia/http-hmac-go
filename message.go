package httphmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func (h *Headers) String() string {
	var b bytes.Buffer

	for k, v := range h.values {
		b.WriteString(k + ": " + v)
		b.WriteString("\n")
	}

	if b.Len() == 0 {
		b.WriteString("\n")
	}

	return b.String()
}

type Message struct {
	Method        string
	BodyHash      string
	ContentType   string
	Date          string
	CustomHeaders *Headers
	Resource      *url.URL
}

func NewMessage(r *http.Request, headers ...[]string) *Message {

	h := NewHeaders()
	if len(headers) > 0 {
		for _, header := range headers[0] {
			h.Set(header, r.Header.Get(header))
		}
	}

	return &Message{
		r.Method,
		HashBody(r.Body),
		r.Header.Get("Content-Type"),
		r.Header.Get("Date"),
		h,
		r.URL,
	}
}

func (m *Message) Write() []byte {
	var b bytes.Buffer

	b.WriteString(strings.ToUpper(m.Method))
	b.WriteString("\n")

	b.WriteString(m.BodyHash)
	b.WriteString("\n")

	b.WriteString(strings.ToLower(m.ContentType))
	b.WriteString("\n")

	b.WriteString(m.Date)
	b.WriteString("\n")

	b.WriteString(m.CustomHeaders.String())

	b.WriteString(m.Resource.RequestURI())

	return b.Bytes()
}

func (m *Message) Sign(digest func() hash.Hash, secret string) string {
	h := hmac.New(digest, []byte(secret))
	h.Write(m.Write())
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func HashBody(body io.ReadCloser) string {
	b := new(bytes.Buffer)
	b.ReadFrom(body)

	h := md5.New()
	h.Write(b.Bytes())
	return hex.EncodeToString(h.Sum(nil))
}

type Headers struct {
	values map[string]string
}

func NewHeaders() *Headers {
	return &Headers{
		values: make(map[string]string),
	}
}

func (h *Headers) Set(header, value string) *Headers {
	h.values[strings.ToLower(header)] = value
	return h
}
