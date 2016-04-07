package legacy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/acquia/http-hmac-go/signers"
	//"github.com/dchest/uniuri"
	"hash"
	"html"
	"io/ioutil"
	"log"
	"os"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sort"
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
	return &SearchSigner{
		Digester: &signers.Digester{
			Digest: digest,
		},
		Identifiable: &signers.Identifiable{
			IdRegex: nil,
		},
		respSigner: NewSearchResponseSigner(digest),
	}, nil
}

func (v *SearchSigner) GetResponseSigner() signers.ResponseSigner {
	return v.respSigner
}

func (v *SearchSigner) Check(r *http.Request, secret string) *signers.AuthenticationError {
	var hash string
	var path_and_query string
	var request_time int64
	var nonce string
    request_time = time.Now().Unix()
    nonce = getNonce()

    // get acquia_solr_time
    acquia_solr_time, err := r.Cookie("acquia_solr_time").Value
    if err != nil {
		return signers.Errorf(403, signers.ErrorTypeMissingRequiredHeader, "Missing required cookie: %s", err.Error())
	}
	logger.Print("acquia_solr_time" + acquia_solr_time)
    
    // get acquia_solr_nonce
    acquia_solr_nonce, err := r.Cookie("acquia_solr_nonce").Value
    if err != nil {
		return signers.Errorf(403, signers.ErrorTypeMissingRequiredHeader, "Missing required cookie: %s", err.Error())
	}
	logger.Print("acquia_solr_nonce" + acquia_solr_nonce)

    // get acquia_solr_hmac
    acquia_solr_hmac, err := r.Cookie("acquia_solr_hmac").Value
    if err != nil {
		return signers.Errorf(403, signers.ErrorTypeMissingRequiredHeader, "Missing required cookie: %s", err.Error())
	}
	logger.Print("acquia_solr_hmac" + acquia_solr_hmac)

	// Check if request time is more than fifteen minutes before or after current time
	timestamp, err := strconv.ParseInt(acquia_solr_time), 10, 64)
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
		body, err := signers.ReadBody(req)
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

    if hash != acquia_solr_hmac {
    	return signers.Errorf(403, signers.ErrorTypeInvalidRequiredHeader, "Hash in acquia_solr_hmac does not match expected value")
    }
    // All checks passed, request is authorized
    return nil
}

function addCookiestoRequest() {
    r.AddCookie(&http.Cookie{Name: "acquia_solr_time", Value: strconv.FormatInt(request_time, 10)})
    logger.Print("request_time: " + strconv.FormatInt(request_time, 10))
    r.AddCookie(&http.Cookie{Name: "acquia_solr_nonce", Value: nonce})
    logger.Print("nonce: " + nonce) 
    r.AddCookie(&http.Cookie{Name: "acquia_solr_hmac", Value: hash})
    logger.Print("hash: " + hash)
}

func getNonce() (string) {
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