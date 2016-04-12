package legacy

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/acquia/http-hmac-go/signers"
	"hash"
	"io/ioutil"
	"log"
	"os"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var logger = log.New(os.Stdout, "", log.LstdFlags)

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

func (v *SearchSigner) HashBody(req *http.Request) (string, *signers.AuthenticationError) {
	data, err := signers.ReadBody(req)
	if err != nil {
		return "", signers.Errorf(500, signers.ErrorTypeInternalError, "Failed to read request body: %s", err.Error())
	}
	return v.HashBytes(data), nil
}

func (v *SearchSigner) HashBytes(b []byte) string {
	h := sha256.New()
	h.Write(b)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (v *SearchSigner) GetResponseSigner() signers.ResponseSigner {
	return v.respSigner
}

func (v *SearchSigner) Sign(r *http.Request, authHeaders map[string]string, secret string) (string, *signers.AuthenticationError) {

	var hash string
	var path_and_query string
	var secret_key string
	var request_time int64
	var nonce string
	var core_name string

	// get / validate headers
	auth_headers := ParseAuthHeaders(r)
    if auth_headers["acquia_solr_time"] == "" {
		return "", signers.Errorf(403, signers.ErrorTypeMissingRequiredHeader, "Missing required cookie: acquia_solr_time")
    }
    if auth_headers["acquia_solr_nonce"] == "" {
		return "", signers.Errorf(403, signers.ErrorTypeMissingRequiredHeader, "Missing required cookie: acquia_solr_nonce")
    }
    if auth_headers["acquia_solr_hmac"] == "" {
		return "", signers.Errorf(403, signers.ErrorTypeMissingRequiredHeader, "Missing required cookie: acquia_solr_hmac")
    }

	// core name is second part of path
	core_name = strings.Split(r.URL.Path, "/")[1]
	secret_key = getSecretKey(core_name)
    request_time = time.Now().Unix()
    nonce = getNonce()

	body, err := ioutil.ReadAll(r.Body)
    if err != nil {
		return "", signers.Errorf(500, signers.ErrorTypeInternalError, "Failed to read request body: %s", err.Error())
    }

    if r.Method == "POST" {
	    hash = generateSignature(string(body), request_time, secret_key)
	    logger.Print("body: " + string(body))
    } else {
        path_and_query = r.URL.Path + "?" + r.URL.RawQuery;
        hash = generateSignature(path_and_query, request_time, secret_key);
        logger.Print("Path and Query: " + path_and_query)
    }

    return hash, nil
}


func (v *SearchSigner) ParseAuthHeaders(r *http.Request) map[string]string {

	auth_headers := map[string]string{}
	auth_fields := []string {
		"acquia_solr_time",
		"acquia_solr_nonce",
		"acquia_solr_hmac",
	}

	for index, field_name := range auth_fields {
	    auth_cookie, err := r.Cookie(field_name)
	    if err != nil {
			logger.Print("Error retrieving [%s]", field_name)
		}
		auth_headers[field_name] = auth_cookie.Value
		logger.Print("[%s]: [%s]", field_name, auth_cookie.Value)
    }
    return auth_headers
}

func (v *SearchSigner) Check(r *http.Request, secret string) *signers.AuthenticationError {
	var hash string
	var path_and_query string
	var request_time int64
    request_time = time.Now().Unix()

	auth_headers := ParseAuthHeaders(r)

    if auth_headers["acquia_solr_time"] == "" {
		return signers.Errorf(403, signers.ErrorTypeMissingRequiredHeader, "Missing required cookie: acquia_solr_time")
    }
    if auth_headers["acquia_solr_nonce"] == "" {
		return signers.Errorf(403, signers.ErrorTypeMissingRequiredHeader, "Missing required cookie: acquia_solr_nonce")
    }
    if auth_headers["acquia_solr_hmac"] == "" {
		return signers.Errorf(403, signers.ErrorTypeMissingRequiredHeader, "Missing required cookie: acquia_solr_hmac")
    }

	// Check if request time is more than fifteen minutes before or after current time
	timestamp, err := strconv.ParseInt(auth_headers["acquia_solr_time"], 10, 64)
	if err != nil {
		return signers.Errorf(403, signers.ErrorTypeInvalidRequiredHeader, "Timestamp parse error: %s", err.Error())
	}
	if timestamp > signers.Now().Unix()+900 {
		return signers.Errorf(403, signers.ErrorTypeTimestampRangeError, "Timestamp given in X-Authorization-Timestamp (%d) was too far in the future.", timestamp)
	}
	if timestamp < signers.Now().Unix()-900 {
		return signers.Errorf(403, signers.ErrorTypeTimestampRangeError, "Timestamp given in X-Authorization-Timestamp (%d) was too far in the past.", timestamp)
	}

	// Request method determines what we hash
    if r.Method == "POST" {
		body, err := signers.ReadBody(r)
		if err != nil {
			return signers.Errorf(500, signers.ErrorTypeInternalError, "Failed to read request body: %s", err.Error())
		}
		// 
	    hash = generateSignature(string(body), request_time, secret)
	    logger.Print("body: " + string(body))

    } else {
        path_and_query = r.URL.Path + "?" + r.URL.RawQuery
        hash = generateSignature(path_and_query, request_time, secret)
        logger.Print("Path and Query: " + path_and_query)
    }

    if hash != auth_headers["acquia_solr_hmac"] {
    	return signers.Errorf(403, signers.ErrorTypeInvalidRequiredHeader, "Hash in acquia_solr_hmac does not match expected value")
    }
    // All checks passed, request is authorized
    return nil
}

func (v *SearchSigner) SignDirect(req *http.Request, authHeaders map[string]string, secret string) *signers.AuthenticationError {

	var hash string
	var path_and_query string
	var secret_key string
	var request_time int64
	var nonce string

	// core name is second part of path
	core_name = strings.Split(r.URL.Path, "/")[1]
	secret_key = getSecretKey(core_name)
	request_time = time.Now().Unix()
	nonce = getNonce()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return signers.Errorf(500, signers.ErrorTypeInternalError, "Failed to read request body: %s", err.Error())
	}

    if r.Method == "POST" {
	    hash = generateSignature(string(body), request_time, secret_key)
	    logger.Print("body: " + string(body))
    } else {
        path_and_query = r.URL.Path + "?" + r.URL.RawQuery;
        hash = generateSignature(path_and_query, request_time, secret_key);
        logger.Print("Path and Query: " + path_and_query)
    }

    r.AddCookie(&http.Cookie{Name: "acquia_solr_time", Value: strconv.FormatInt(request_time, 10)})
    logger.Print("request_time: " + strconv.FormatInt(request_time, 10))
    r.AddCookie(&http.Cookie{Name: "acquia_solr_nonce", Value: nonce})
    logger.Print("nonce: " + nonce) 
    r.AddCookie(&http.Cookie{Name: "acquia_solr_hmac", Value: hash})
    logger.Print("hash: " + hash)

}

func getSecretKey (core_name string) (string) {
	var secret_key string
	secret_key = "not-a-real-key"
	return secret_key
}

func (v *SearchSigner) GenerateAuthorization(r *http.Request, authHeaders map[string]string, signature string) (string, *signers.AuthenticationError) {
	//TODO: this function was added because signers.Signer requires it
	return fmt.Sprintf("Search GenerateAuthorization"), nil
}

func (v *SearchSigner) GetIdentificationRegex() *regexp.Regexp {
	return v.IdRegex5
}

func getNonce() (string) {
	//"github.com/dchest/uniuri"
	//var char_list = []byte(" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}")
	//TODO: base64 encode before returning
	//return NewLenChars(24, char_list)
	return "ABCDEFGHIJKLMNOPQRSTUVWX"
}

func generateSignature(content string, request_time int64, secret string) (string) {
	data := strconv.FormatInt(request_time, 10) + getNonce() + content;
    key := []byte(secret)                                                        
	h := hmac.New(sha1.New, key)                                                    
	h.Write([]byte(data))                                                    
	hmac_string := hex.EncodeToString(h.Sum(nil))
	return hmac_string
}