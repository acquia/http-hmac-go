package legacy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/acquia/http-hmac-go/signers/v1"
	"net/http"
	"strings"
)

func V1SignUrlless(req *http.Request, id string, secret string) string {
	v, err := v1.NewV1Signer(sha256.New)
	if err != nil {
		return ""
	}
	bodyhash, err := v.HashBody(req)
	if err != nil {
		return ""
	}
	var b bytes.Buffer

	b.WriteString(strings.ToUpper(req.Method))
	b.WriteString("\n")

	b.WriteString(bodyhash)
	b.WriteString("\n")

	b.WriteString(strings.ToLower(req.Header.Get("Content-Type")))
	b.WriteString("\n")

	b.WriteString(req.Header.Get("Date"))
	b.WriteString("\n")
	b.WriteString("\n")

	h := hmac.New(v.Digest, []byte(secret))
	h.Write(b.Bytes())
	hsm := h.Sum(nil)
	return fmt.Sprintf("Acquia %s:%s", id, base64.StdEncoding.EncodeToString(hsm))
}
