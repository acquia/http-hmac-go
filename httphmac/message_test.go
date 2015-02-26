package httphmac

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"testing"
)

func NewTestMessage() *Message {
	h := NewHeaders()
	h.Set("Custom1", "Value1")

	r, _ := url.Parse("http://example.com/resource/1?key=value")

	return &Message{
		Method:        "post",
		BodyHash:      "9473fdd0d880a43c21b7778d34872157", // MD5 of "test content"
		ContentType:   "text/plain",
		Date:          "Fri, 19 Mar 1982 00:00:04 GMT",
		CustomHeaders: h,
		Resource:      r,
	}
}

func NewTestLongText() string {
	return "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque scelerisque convallis dapibus. Phasellus ac rhoncus felis, sit amet lacinia justo. Cras at urna ut augue mollis porttitor. Duis ut vehicula orci. Nulla ex justo, lobortis at neque et, dapibus bibendum nunc. Vivamus porttitor convallis nulla, in sodales augue ullamcorper vel. Nunc ultricies est eu tincidunt luctus. Maecenas ac libero luctus, faucibus quam vitae, placerat purus. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Aenean bibendum dui a nunc scelerisque ornare. Sed rhoncus mi finibus arcu dapibus, eu mattis ex fringilla. Cras molestie aliquam mi a tincidunt. Integer commodo dictum consectetur. Suspendisse enim velit, porta quis semper ac, condimentum sed ligula. Nulla scelerisque consequat metus faucibus tempus. Cras eros est, bibendum et felis sed, placerat facilisis arcu. Phasellus elit dolor, dictum nec ex sit amet, hendrerit maximus turpis. Quisque eget erat non nunc bibendum ultricies. Phasellus ante ipsum, lobortis at dictum sed, tincidunt nec lorem. Donec venenatis est vitae dui euismod, sed iaculis erat ultrices. Nullam eget metus placerat metus dignissim sodales. Quisque commodo non sem vitae tristique. Integer blandit nunc massa, non cursus massa aliquet sed. Suspendisse urna ipsum, tempus at dapibus vel, venenatis id risus. Etiam commodo fringilla mi, vel molestie augue. Phasellus pretium mollis purus. Duis sollicitudin ac elit id pulvinar. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Morbi imperdiet tincidunt tortor, at ullamcorper tellus sodales ut. Nulla facilisi. Proin ac fringilla arcu. Suspendisse cursus diam nunc, ac malesuada lectus finibus quis. Suspendisse ut ex diam. In hac habitasse platea dictumst. Praesent vitae enim a ante pharetra varius ac ut mauris. Nulla odio nulla, scelerisque nec sollicitudin id, porta ut felis. In auctor imperdiet felis sed finibus. Ut nibh quam, iaculis finibus scelerisque sed, vestibulum ut justo. Fusce lacinia, velit a feugiat gravida, sapien leo tempus nibh, quis ultrices sem arcu convallis arcu. Cras eu odio elit. Sed in porta felis. Sed non lectus et libero aliquet imperdiet eu ut tortor."
}

func NewTestRequest() *http.Request {
	req, _ := http.NewRequest("get", "http://example.com/resource/1?key=value",  nil)
	return req
}

func TestSign(t *testing.T) {
	m := NewTestMessage()
	s := m.Sign(sha1.New, "secret-key")
	if s != "QRMtvnGmlP1YbaTwpWyB/6A8dRU=" {
		t.Fail()
	}
}

func TestSignRequest(t *testing.T) {
	req := NewTestRequest()
	m := NewMessage(req)
	s := m.Sign(sha1.New, "secret-key")
	if s != "7Tq3+JP3lAu4FoJz81XEx5+qfOc=" {
		t.Fail()
	}
}

func BenchmarkSignSha1LongText(b *testing.B) {
	t := NewTestLongText()
	m := NewTestMessage()
	m.BodyHash = t
	d := sha1.New
	for i := 0; i < b.N; i++ {
		m.Sign(d, "secret-key")
	}
}

func BenchmarkSignSha256LongText(b *testing.B) {
	t := NewTestLongText()
	m := NewTestMessage()
	m.BodyHash = t
	d := sha256.New
	for i := 0; i < b.N; i++ {
		m.Sign(d, "secret-key")
	}
}

func BenchmarkSignSha1LongTextMD5(b *testing.B) {
	t := NewTestLongText()
	m := NewTestMessage()
	d := sha1.New
	for i := 0; i < b.N; i++ {
		md5s := md5.Sum([]byte(t))
		m.BodyHash = hex.EncodeToString(md5s[:])
		m.Sign(d, "secret-key")
	}
}

func BenchmarkSignSha256LongTextMD5(b *testing.B) {
	t := NewTestLongText()
	m := NewTestMessage()
	m.BodyHash = t
	d := sha256.New
	for i := 0; i < b.N; i++ {
		md5s := md5.Sum([]byte(t))
		m.BodyHash = hex.EncodeToString(md5s[:])
		m.Sign(d, "secret-key")
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
