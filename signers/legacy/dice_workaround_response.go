package legacy

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"github.com/acquia/http-hmac-go/signers"
	"hash"
	"net/http"
)

type V2DiceLegacyResponseSigner struct {
	*signers.Digester
}

func NewV2DiceLegacyResponseSigner(digest func() hash.Hash) *V2DiceLegacyResponseSigner {
	return &V2DiceLegacyResponseSigner{
		Digester: &signers.Digester{
			Digest: digest,
		},
	}
}

func (v *V2DiceLegacyResponseSigner) CreateSignable(req *http.Request, authHeaders map[string]string, rw *signers.SignableResponseWriter) []byte {
	var b bytes.Buffer
	b.WriteString(authHeaders["nonce"])
	b.WriteString("\n")
	b.WriteString(req.Header.Get("X-Authorization-Timestamp"))
	b.WriteString("\n")
	b.WriteString(rw.Body.String())
	return b.Bytes()
}

func (v *V2DiceLegacyResponseSigner) SignResponse(req *http.Request, rw *signers.SignableResponseWriter, secret string) (string, *signers.AuthenticationError) {
	authHeaders := ParseAuthHeadersDice(req)
	if _, ok := authHeaders["nonce"]; !ok {
		return "", signers.Errorf(403, signers.ErrorTypeInvalidAuthHeader, "Nonce must be present in authentication headers.")
	}
	if req.Header.Get("X-Authorization-Timestamp") == "" {
		return "", signers.Errorf(403, signers.ErrorTypeMissingRequiredHeader, "Authorization timestamp for request is required.")
	}
	// First version of Acquia Auth Proxy for Dice mistakenly switched the order
	// of the hmac signing function.
	// Calculate message Hash Legacy
	// It also did not decode the secret key from base64.
	b := v.CreateSignable(req, authHeaders, rw)
	h := hmac.New(v.Digest, b)
	h.Write([]byte(secret))
	hsm := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(hsm), nil
}

func (v *V2DiceLegacyResponseSigner) SignResponseDirect(req *http.Request, rw *signers.SignableResponseWriter, secret string) *signers.AuthenticationError {
	rsig, err := v.SignResponse(req, rw, secret)
	if err != nil {
		return err
	}
	rw.Header().Set("X-Server-Authorization-HMAC-SHA256", rsig)
	return nil
}

func (v *V2DiceLegacyResponseSigner) Check(req *http.Request, resp *http.Response, secret string) *signers.AuthenticationError {
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

func (v *V2DiceLegacyResponseSigner) SetTrailer(rw http.ResponseWriter) {
	rw.Header().Add("Trailer", "X-Server-Authorization-HMAC-SHA256")
}
