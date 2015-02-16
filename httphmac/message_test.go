package httphmac

import (
	"crypto/sha1"
	"crypto/sha256"
	"net/url"
	"testing"
)

func NewTestMessage() *Message {
	h := NewHeaders()
	h.Set("Custom1", "Value1")

	r, _ := url.Parse("http://example.com/resource/1?key=value")

	return &Message{
		Method:        "get",
		BodyHash:      "9473fdd0d880a43c21b7778d34872157", // MD5 of "test content"
		ContentType:   "text/plain",
		Date:          "Fri, 19 Mar 1982 00:00:04 GMT",
		CustomHeaders: h,
		Resource:      r,
	}
}

func TestSign(t *testing.T) {
	m := NewTestMessage()
	s := m.Sign(sha1.New, "secret-key")
	if s != "0Qub9svYlxjAr8OO7N0/3u0sohs=" {
		t.Fail()
	}
}

func BenchmarkSignSha1(b *testing.B) {
	m := NewTestMessage()
	d := sha1.New
	for i := 0; i < b.N; i++ {
		m.Sign(d, "secret-key")
	}
}

func BenchmarkSignSha256(b *testing.B) {
	m := NewTestMessage()
	d := sha256.New
	for i := 0; i < b.N; i++ {
		m.Sign(d, "secret-key")
	}
}
