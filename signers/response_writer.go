package signers

import (
	"bytes"
	"net/http"
)

type SignableResponseWriter struct {
	http.ResponseWriter
	code int
	Body bytes.Buffer
}

type dummyResponseWriter struct {
	header http.Header
}

func newDummyResponseWriter() http.ResponseWriter {
	return &dummyResponseWriter{
		header: MakeHeader(map[string][]string{}),
	}
}
func (d *dummyResponseWriter) Header() http.Header {
	return d.header
}
func (d *dummyResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}
func (d *dummyResponseWriter) WriteHeader(i int) {}

func NewDummySignableResponseWriter(body []byte) *SignableResponseWriter {
	ret := NewSignableResponseWriter(newDummyResponseWriter())
	ret.Write(body)
	return ret
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
	return s.Body.Write(b)
}

func (s *SignableResponseWriter) WriteHeader(status int) {
	s.code = status
}

func (s *SignableResponseWriter) Close() (int, error) {
	s.ResponseWriter.WriteHeader(s.code)
	return s.ResponseWriter.Write(s.Body.Bytes())
}
