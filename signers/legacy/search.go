package legacy

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"github.com/acquia/http-hmac-go/signers"
	"hash"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"
)

var logger = log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile)

type SearchSigner struct {
	*signers.Digester
	*signers.Identifiable
	respSigner *SearchResponseSigner
}

func NewSearchSigner(digest func() hash.Hash) (*SearchSigner, *signers.AuthenticationError) {
	re, err := regexp.Compile("(?i)^\\s*acquia_solr_time.*?$")
	if err != nil {
		return nil, signers.Errorf(500, signers.ErrorTypeInternalError, "Could not compile regular expression for identifier: %s", err.Error())
	}

	return &SearchSigner{
		Digester: &signers.Digester{
			Digest: digest,
		},
		Identifiable: &signers.Identifiable{
			IdRegex: re,
		},
		respSigner: NewSearchResponseSigner(digest),
	}, nil
}

func (v *SearchSigner) Sign(r *http.Request, authHeaders map[string]string, secret string) (string, *signers.AuthenticationError) {

	var hash string
	var path_and_query string
	var request_time int64

	// get / validate headers
	auth_headers := v.ParseAuthHeaders(r)

	request_time = time.Now().Unix()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return "", signers.Errorf(500, signers.ErrorTypeInternalError, "Failed to read request body: %s", err.Error())
	}

	if r.Method == "POST" {
		hash = generateSignature(string(body), request_time, secret, auth_headers["acquia_solr_nonce"])
	} else {
		path_and_query = r.URL.Path + "?" + r.URL.RawQuery
		hash = generateSignature(path_and_query, request_time, secret, auth_headers["acquia_solr_nonce"])
	}

	return hash, nil
}

func (v *SearchSigner) Check(r *http.Request, secret string) *signers.AuthenticationError {
	var hash string
	var path_and_query string

	auth_headers := v.ParseAuthHeaders(r)

	// Check if request time is more than fifteen minutes before or after current time
	request_timestamp, err := strconv.ParseInt(auth_headers["acquia_solr_time"], 10, 64)
	if err != nil {
		return signers.Errorf(403, signers.ErrorTypeInvalidRequiredHeader, "Timestamp parse error: %s", err.Error())
	}
	if request_timestamp > signers.Now().Unix()+900 {
		return signers.Errorf(403, signers.ErrorTypeTimestampRangeError, "Timestamp given in X-Authorization-Timestamp (%d) was too far in the future.", request_timestamp)
	}
	if request_timestamp < signers.Now().Unix()-900 {
		return signers.Errorf(403, signers.ErrorTypeTimestampRangeError, "Timestamp given in X-Authorization-Timestamp (%d) was too far in the past.", request_timestamp)
	}

	// Request method determines what we hash
	if r.Method == "POST" {
		body, err := signers.ReadBody(r)
		if err != nil {
			return signers.Errorf(500, signers.ErrorTypeInternalError, "Failed to read request body: %s", err.Error())
		}
		hash = generateSignature(string(body), request_timestamp, secret, auth_headers["acquia_solr_nonce"])

	} else {
		path_and_query = r.URL.Path + "?" + r.URL.RawQuery
		hash = generateSignature(path_and_query, request_timestamp, secret, auth_headers["acquia_solr_nonce"])
	}

	if hash != auth_headers["acquia_solr_hmac"] {
		logger.Print("Expected: ", hash)
		logger.Print("Received: ", auth_headers["acquia_solr_hmac"])
		return signers.Errorf(403, signers.ErrorTypeInvalidRequiredHeader, "Hash in acquia_solr_hmac does not match expected value")
	}
	// All checks passed, request is authorized
	return nil
}

func (v *SearchSigner) SignDirect(r *http.Request, authHeaders map[string]string, secret string) *signers.AuthenticationError {

	var hash string
	var path_and_query string
	var request_time int64

	request_time = time.Now().Unix()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return signers.Errorf(500, signers.ErrorTypeInternalError, "Failed to read request body: %s", err.Error())
	}

	if r.Method == "POST" {
		hash = generateSignature(string(body), request_time, secret, authHeaders["acquia_solr_nonce"])
	} else {
		path_and_query = r.URL.Path + "?" + r.URL.RawQuery
		hash = generateSignature(path_and_query, request_time, secret, authHeaders["acquia_solr_nonce"])
	}

	r.AddCookie(&http.Cookie{Name: "acquia_solr_time", Value: strconv.FormatInt(request_time, 10)})
	r.AddCookie(&http.Cookie{Name: "acquia_solr_nonce", Value: authHeaders["acquia_solr_nonce"]})
	r.AddCookie(&http.Cookie{Name: "acquia_solr_hmac", Value: hash})

	return nil
}

func generateSignature(content string, request_time int64, secret string, nonce string) string {
	data := strconv.FormatInt(request_time, 10) + nonce + content
	key := []byte(secret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(data))
	hmac_string := hex.EncodeToString(h.Sum(nil))
	return hmac_string
}

func (v *SearchSigner) ParseAuthHeaders(req *http.Request) map[string]string {
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
	return auth_headers
}

func (v *SearchSigner) GetResponseSigner() signers.ResponseSigner {
	return v.respSigner
}

func (v *SearchSigner) Version() int {
	return 0
}

func (v *SearchSigner) HashBody(r *http.Request) (string, *signers.AuthenticationError) {
	panic("Function HashBody is not implemented")
	return "", nil
}

func (v *SearchSigner) GetIdentificationRegex() *regexp.Regexp {
	panic("Function GetIdentificationRegex is not implemented")
	return v.IdRegex
}

func (v *SearchSigner) GenerateAuthorization(r *http.Request, authHeaders map[string]string, signature string) (string, *signers.AuthenticationError) {
	panic("Function GenerateAuthorization is not implemented")
	return "", nil
}
