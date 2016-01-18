package v2

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"github.com/acquia/http-hmac-go/signers"
	"hash"
	"net/http"
)

type V2ResponseSigner struct {
	*signers.Digester
}

func NewV2ResponseSigner(digest func() hash.Hash) *V2ResponseSigner {
	return &V2ResponseSigner{
		Digester: &signers.Digester{
			Digest: digest,
		},
	}
}

func (v *V2ResponseSigner) CreateSignable(req *http.Request, authHeaders map[string]string, rw *signers.SignableResponseWriter) []byte {
	var b bytes.Buffer
	b.WriteString(authHeaders["nonce"])
	b.WriteString("\n")
	b.WriteString(req.Header.Get("X-Authorization-Timestamp"))
	b.WriteString("\n")
	b.WriteString(rw.Body.String())
	return b.Bytes()
}

func (v *V2ResponseSigner) SignResponse(req *http.Request, rw *signers.SignableResponseWriter, secret string) (string, *signers.AuthenticationError) {
	authHeaders := ParseAuthHeaders(req)
	if _, ok := authHeaders["nonce"]; !ok {
		return "", signers.Errorf(403, signers.ErrorTypeInvalidAuthHeader, "Nonce must be present in authentication headers.")
	}
	if req.Header.Get("X-Authorization-Timestamp") == "" {
		return "", signers.Errorf(403, signers.ErrorTypeMissingRequiredHeader, "Authorization timestamp for request is required.")
	}
	decoded, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", signers.Errorf(403, signers.ErrorTypeOutdatedKeypair, "The provided secret key is not in a valid base64 format: %s", err.Error())
	}
	h := hmac.New(v.Digest, decoded)
	b := v.CreateSignable(req, authHeaders, rw)
	h.Write(b)
	hsm := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(hsm), nil
}

func (v *V2ResponseSigner) SignResponseDirect(req *http.Request, rw *signers.SignableResponseWriter, secret string) *signers.AuthenticationError {
	rsig, err := v.SignResponse(req, rw, secret)
	if err != nil {
		return err
	}
	rw.Header().Set("X-Server-Authorization-HMAC-SHA256", rsig)
	return nil
}

func (v *V2ResponseSigner) Check(req *http.Request, resp *http.Response, secret string) *signers.AuthenticationError {
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

func (v *V2ResponseSigner) SetTrailer(rw http.ResponseWriter) {
	rw.Header().Add("Trailer", "X-Server-Authorization-HMAC-SHA256")
}
