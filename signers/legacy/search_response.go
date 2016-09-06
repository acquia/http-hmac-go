package legacy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"github.com/acquia/http-hmac-go/signers"
	"hash"
	"net/http"
)

type SearchResponseSigner struct {
	*signers.Digester
}

func NewSearchResponseSigner(digest func() hash.Hash) *SearchResponseSigner {
	return &SearchResponseSigner{
		Digester: &signers.Digester{
			Digest: digest,
		},
	}
}

func (v *SearchResponseSigner) CreateSignable(body string, nonce string) []byte {
	var b bytes.Buffer
	b.WriteString(nonce)
	b.WriteString(body)
	return b.Bytes()
}

func (v *SearchResponseSigner) SignResponse(req *http.Request, rw *signers.SignableResponseWriter, secret string) (string, *signers.AuthenticationError) {
	auth_headers := map[string]string{}
	auth_fields := []string{
		"acquia_solr_time",
		"acquia_solr_nonce",
		"acquia_solr_hmac",
	}

	for _, field_name := range auth_fields {
		auth_cookie, err := req.Cookie(field_name)
		if err != nil {
			logger.Print("Error retrieving:", field_name)
		} else {
			auth_headers[field_name] = auth_cookie.Value
		}
	}

	if _, ok := auth_headers["acquia_solr_nonce"]; !ok {
		return "", signers.Errorf(403, signers.ErrorTypeInvalidAuthHeader, "Nonce must be present in authentication headers.")
	}

	b := v.CreateSignable(rw.Body.String(), auth_headers["acquia_solr_nonce"])
	h := hmac.New(sha1.New, []byte(secret))
	h.Write([]byte(b))
	hmac_string := hex.EncodeToString(h.Sum(nil))
	return hmac_string, nil
}

func (v *SearchResponseSigner) SignResponseDirect(req *http.Request, rw *signers.SignableResponseWriter, secret string) *signers.AuthenticationError {
	rsig, err := v.SignResponse(req, rw, secret)
	if err != nil {
		return err
	}
	rw.Header().Set("pragma", "hmac_digest=" + rsig + ";")
	return nil
}

func (v *SearchResponseSigner) Check(req *http.Request, resp *http.Response, secret string) *signers.AuthenticationError {
	got := resp.Header.Get("X-Server-Authorization-HMAC-SHA256")
	if got == "" {
		return signers.Errorf(403, signers.ErrorTypeInvalidAuthHeader, "Signature missing from response.")
	}
	rb, err := signers.ReadResponseBody(resp)
	if err != nil {
		return signers.Errorf(500, signers.ErrorTypeUnknown, "Cannot read response body: "+err.Error())
	}
	srw := signers.NewDummySignableResponseWriter(rb)
	sig, serr := v.SignResponse(req, srw, secret)
	if serr != nil {
		return serr
	}
	if sig != got {
		return signers.Errorf(403, signers.ErrorTypeSignatureMismatch, "Signature does not match expected signature.")
	}
	return nil
}

func (v *SearchResponseSigner) SetTrailer(rw http.ResponseWriter) {
	rw.Header().Add("Trailer", "X-Server-Authorization-HMAC-SHA256")
}
