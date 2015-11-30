package signers

import (
	"bytes"
	"net/http"
)

type SignableResponseWriter struct {
	http.ResponseWriter
	Body bytes.Buffer
}

func NewSignableResponseWriter(h http.ResponseWriter) *SignableResponseWriter {
	return &SignableResponseWriter{
		ResponseWriter: h,
		Body:           bytes.Buffer{},
	}
}

func (s *SignableResponseWriter) Header() http.Header {
	return s.ResponseWriter.Header()
}

func (s *SignableResponseWriter) Write(b []byte) (int, error) {
	s.Body.Write(b)
	return s.ResponseWriter.Write(b)
}

func (s *SignableResponseWriter) WriteHeader(status int) {
	s.ResponseWriter.WriteHeader(status)
}
