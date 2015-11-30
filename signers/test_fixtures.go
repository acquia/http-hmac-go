package signers

import (
	"crypto/sha1"
	"crypto/sha256"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type ResponseFixture struct {
	Expected map[string]string
	Response *SignableResponseWriter
}

type TestFixture struct {
	TestName    string
	Digest      func() hash.Hash
	Expected    map[string]string
	Request     *http.Request
	AuthHeaders map[string]string
	SecretKey   string
	Response    *ResponseFixture
	SystemTime  int64
	ErrorType   map[string]ErrorType
}

type CompatibilityTestFixture struct {
	TestName   string
	Digest     func() hash.Hash
	Request    *http.Request
	SecretKey  string
	SystemTime int64
	Expected   string
}

func MakeHeader(m map[string][]string) http.Header {
	h := http.Header{}
	for k, vs := range m {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	return h
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

func PrepareResponseWriter(b string) *SignableResponseWriter {
	s := &SignableResponseWriter{
		ResponseWriter: newDummyResponseWriter(),
	}
	s.Write([]byte(b))
	return s
}

func SilentURLParse(uri string) *url.URL {
	u, _ := url.Parse(uri)
	return u
}

func MakeBody(content string) io.ReadCloser {
	return ioutil.NopCloser(strings.NewReader(content))
}

var Fixtures []*TestFixture = []*TestFixture{
	&TestFixture{
		TestName:   "v1 - valid request without additional signed headers - invalid header in v2",
		SystemTime: 1432075982,
		Digest:     sha1.New,
		Expected: map[string]string{
			"v1": "6DQcBYwaKdhRm/eNBKIN2jM8HF8=",
		},
		Request: &http.Request{
			Method: "POST",
			Body:   MakeBody("test content"),
			Header: MakeHeader(map[string][]string{
				"Content-Type": []string{"text/plain"},
				"Date":         []string{"Fri, 19 Mar 1982 00:00:04 GMT"},
			}),
			URL: SilentURLParse("http://example.com/resource/1?key=value"),
		},
		AuthHeaders: map[string]string{},
		SecretKey:   "secret-key",
		ErrorType: map[string]ErrorType{
			"v2": ErrorTypeInvalidAuthHeader,
		},
	},
	&TestFixture{
		TestName:   "v1 - valid request with additional signed headers - invalid header in v2",
		SystemTime: 1432075982,
		Digest:     sha1.New,
		Expected: map[string]string{
			"v1": "QRMtvnGmlP1YbaTwpWyB/6A8dRU=",
		},
		Request: &http.Request{
			Method: "POST",
			Body:   MakeBody("test content"),
			Header: MakeHeader(map[string][]string{
				"Content-Type": []string{"text/plain"},
				"Date":         []string{"Fri, 19 Mar 1982 00:00:04 GMT"},
				"Custom1":      []string{"Value1"},
			}),
			URL: SilentURLParse("http://example.com/resource/1?key=value"),
		},
		AuthHeaders: map[string]string{
			"headers": "Custom1",
		},
		SecretKey: "secret-key",
		ErrorType: map[string]ErrorType{
			"v2": ErrorTypeInvalidAuthHeader,
		},
	},
	&TestFixture{
		TestName:   "v2 - valid GET request",
		SystemTime: 1432075982,
		Digest:     sha256.New,
		Expected: map[string]string{
			"v2": "MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc=",
		},
		Request: &http.Request{
			Method: "GET",
			Header: MakeHeader(map[string][]string{
				"X-Authorization-Timestamp": []string{"1432075982"},
				"Host": []string{"example.acquiapipet.net"},
			}),
			URL: SilentURLParse("https://example.acquiapipet.net/v1.0/task-status/133?limit=10"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Pipet%20service",
			"id":      "efdde334-fe7b-11e4-a322-1697f925ec7b",
			"nonce":   "d1954337-5319-4821-8427-115542e08d10",
			"version": "2.0",
		},
		SecretKey: "W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=",
		Response: &ResponseFixture{
			Expected: map[string]string{
				"v2": "M4wYp1MKvDpQtVOnN7LVt9L8or4pKyVLhfUFVJxHemU=",
			},
			Response: PrepareResponseWriter(`{"id": 133, "status": "done"}`),
		},
		ErrorType: map[string]ErrorType{},
	},
	&TestFixture{
		TestName:   "v2 - valid POST request",
		SystemTime: 1432075982,
		Digest:     sha256.New,
		Expected: map[string]string{
			"v2": "XDBaXgWFCY3aAgQvXyGXMbw9Vds2WPKJe2yP+1eXQgM=",
		},
		Request: &http.Request{
			Method: "POST",
			Body:   MakeBody("{\"method\":\"hi.bob\",\"params\":[\"5\",\"4\",\"8\"]}"),
			Header: MakeHeader(map[string][]string{
				"X-Authorization-Timestamp":      []string{"1432075982"},
				"X-Authorization-Content-SHA256": []string{"6paRNxUA7WawFxJpRp4cEixDjHq3jfIKX072k9slalo="},
				"Content-Type":                   []string{"application/json"},
				"Host":                           []string{"example.acquiapipet.net"},
			}),
			URL: SilentURLParse("https://example.acquiapipet.net/v1.0/task/"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Pipet%20service",
			"id":      "efdde334-fe7b-11e4-a322-1697f925ec7b",
			"nonce":   "d1954337-5319-4821-8427-115542e08d10",
			"version": "2.0",
		},
		SecretKey: "W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=",
		ErrorType: map[string]ErrorType{},
	},
	&TestFixture{
		TestName:   "v2 - request with missing timestamp",
		SystemTime: 1432075982,
		Digest:     sha256.New,
		Expected:   map[string]string{},
		Request: &http.Request{
			Method: "POST",
			Body:   MakeBody("{\"method\":\"hi.bob\",\"params\":[\"5\",\"4\",\"8\"]}"),
			Header: MakeHeader(map[string][]string{
				"X-Authorization-Content-SHA256": []string{"6paRNxUA7WawFxJpRp4cEixDjHq3jfIKX072k9slalo="},
				"Content-Type":                   []string{"application/json"},
				"Host":                           []string{"example.acquiapipet.net"},
			}),
			URL: SilentURLParse("https://example.acquiapipet.net/v1.0/task/"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Pipet%20service",
			"id":      "efdde334-fe7b-11e4-a322-1697f925ec7b",
			"nonce":   "d1954337-5319-4821-8427-115542e08d10",
			"version": "2.0",
		},
		SecretKey: "W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=",
		ErrorType: map[string]ErrorType{
			"v2": ErrorTypeMissingRequiredHeader,
		},
	},
	&TestFixture{
		TestName:   "v2 - request with missing content SHA",
		SystemTime: 1432075982,
		Digest:     sha256.New,
		Expected:   map[string]string{},
		Request: &http.Request{
			Method: "POST",
			Body:   MakeBody("{\"method\":\"hi.bob\",\"params\":[\"5\",\"4\",\"8\"]}"),
			Header: MakeHeader(map[string][]string{
				"X-Authorization-Timestamp": []string{"1432075982"},
				"Content-Type":              []string{"application/json"},
				"Host":                      []string{"example.acquiapipet.net"},
			}),
			URL: SilentURLParse("https://example.acquiapipet.net/v1.0/task/"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Pipet%20service",
			"id":      "efdde334-fe7b-11e4-a322-1697f925ec7b",
			"nonce":   "d1954337-5319-4821-8427-115542e08d10",
			"version": "2.0",
		},
		SecretKey: "W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=",
		ErrorType: map[string]ErrorType{
			"v2": ErrorTypeMissingRequiredHeader,
		},
	},
	&TestFixture{
		TestName:   "v2 - request with mismatching content SHA",
		SystemTime: 1432075982,
		Digest:     sha256.New,
		Expected:   map[string]string{},
		Request: &http.Request{
			Method: "POST",
			Body:   MakeBody("{\"method\":\"hi.bob\",\"params\":[\"5\",\"4\",\"8\"]}"),
			Header: MakeHeader(map[string][]string{
				"X-Authorization-Timestamp":      []string{"1432075982"},
				"X-Authorization-Content-SHA256": []string{"this is not actually a B64 encoded SHA-256 hash and it is unlikely to pass the test"},
				"Content-Type":                   []string{"application/json"},
				"Host":                           []string{"example.acquiapipet.net"},
			}),
			URL: SilentURLParse("https://example.acquiapipet.net/v1.0/task/"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Pipet%20service",
			"id":      "efdde334-fe7b-11e4-a322-1697f925ec7b",
			"nonce":   "d1954337-5319-4821-8427-115542e08d10",
			"version": "2.0",
		},
		SecretKey: "W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=",
		ErrorType: map[string]ErrorType{
			"v2": ErrorTypeInvalidRequiredHeader,
		},
	},
	&TestFixture{
		TestName:   "v2 - request with timestamp in the past",
		SystemTime: 1442075982,
		Digest:     sha256.New,
		Expected:   map[string]string{},
		Request: &http.Request{
			Method: "POST",
			Body:   MakeBody("{\"method\":\"hi.bob\",\"params\":[\"5\",\"4\",\"8\"]}"),
			Header: MakeHeader(map[string][]string{
				"X-Authorization-Timestamp":      []string{"1432075982"},
				"X-Authorization-Content-SHA256": []string{"6paRNxUA7WawFxJpRp4cEixDjHq3jfIKX072k9slalo="},
				"Content-Type":                   []string{"application/json"},
				"Host":                           []string{"example.acquiapipet.net"},
			}),
			URL: SilentURLParse("https://example.acquiapipet.net/v1.0/task/"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Pipet%20service",
			"id":      "efdde334-fe7b-11e4-a322-1697f925ec7b",
			"nonce":   "d1954337-5319-4821-8427-115542e08d10",
			"version": "2.0",
		},
		SecretKey: "W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=",
		ErrorType: map[string]ErrorType{
			"v2": ErrorTypeTimestampRangeError,
		},
	},
	&TestFixture{
		TestName:   "v2 - request with timestamp in the future",
		SystemTime: 1422075982,
		Digest:     sha256.New,
		Expected:   map[string]string{},
		Request: &http.Request{
			Method: "POST",
			Body:   MakeBody("{\"method\":\"hi.bob\",\"params\":[\"5\",\"4\",\"8\"]}"),
			Header: MakeHeader(map[string][]string{
				"X-Authorization-Timestamp":      []string{"1432075982"},
				"X-Authorization-Content-SHA256": []string{"6paRNxUA7WawFxJpRp4cEixDjHq3jfIKX072k9slalo="},
				"Content-Type":                   []string{"application/json"},
				"Host":                           []string{"example.acquiapipet.net"},
			}),
			URL: SilentURLParse("https://example.acquiapipet.net/v1.0/task/"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Pipet%20service",
			"id":      "efdde334-fe7b-11e4-a322-1697f925ec7b",
			"nonce":   "d1954337-5319-4821-8427-115542e08d10",
			"version": "2.0",
		},
		SecretKey: "W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=",
		ErrorType: map[string]ErrorType{
			"v2": ErrorTypeTimestampRangeError,
		},
	},
	&TestFixture{
		TestName:   "v2 - outdated keypair (non-b64 encoded secret key)",
		SystemTime: 1432075982,
		Digest:     sha256.New,
		Expected:   map[string]string{},
		Request: &http.Request{
			Method: "POST",
			Body:   MakeBody("{\"method\":\"hi.bob\",\"params\":[\"5\",\"4\",\"8\"]}"),
			Header: MakeHeader(map[string][]string{
				"X-Authorization-Timestamp":      []string{"1432075982"},
				"X-Authorization-Content-SHA256": []string{"6paRNxUA7WawFxJpRp4cEixDjHq3jfIKX072k9slalo="},
				"Content-Type":                   []string{"application/json"},
				"Host":                           []string{"example.acquiapipet.net"},
			}),
			URL: SilentURLParse("https://example.acquiapipet.net/v1.0/task/"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Pipet%20service",
			"id":      "efdde334-fe7b-11e4-a322-1697f925ec7b",
			"nonce":   "d1954337-5319-4821-8427-115542e08d10",
			"version": "2.0",
		},
		SecretKey: "this is a useless secret key for v2 authentication",
		ErrorType: map[string]ErrorType{
			"v2": ErrorTypeOutdatedKeypair,
		},
	},
}

var CompatFixtures []*CompatibilityTestFixture = []*CompatibilityTestFixture{
	&CompatibilityTestFixture{
		TestName: "Identify a v1 signature",
		Request: &http.Request{
			Method: "GET",
			Header: MakeHeader(map[string][]string{
				"X-Authorization-Timestamp": []string{"1432075982"},
				"Authorization":             []string{`acquia-http-hmac realm="Pipet%20service",id="efdde334-fe7b-11e4-a322-1697f925ec7b",nonce="d1954337-5319-4821-8427-115542e08d10",version="2.0",headers="",signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="`},
				"Host":                      []string{"example.acquiapipet.net"},
			}),
			URL: SilentURLParse("https://example.acquiapipet.net/v1.0/task-status/133?limit=10"),
		},
		SecretKey:  "W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=",
		SystemTime: 1432075982,
		Digest:     sha256.New,
		Expected:   "MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc=",
	},
	&CompatibilityTestFixture{
		TestName: "Identify a v2 signature",
		Request: &http.Request{
			Method: "POST",
			Body:   MakeBody("test content"),
			Header: MakeHeader(map[string][]string{
				"Authorization": []string{"Acquia efdde334-fe7b-11e4-a322-1697f925ec7b:6DQcBYwaKdhRm/eNBKIN2jM8HF8="},
				"Content-Type":  []string{"text/plain"},
				"Date":          []string{"Fri, 19 Mar 1982 00:00:04 GMT"},
			}),
			URL: SilentURLParse("http://example.com/resource/1?key=value"),
		},
		SecretKey:  "secret-key",
		SystemTime: 1432075982,
		Digest:     sha1.New,
		Expected:   "6DQcBYwaKdhRm/eNBKIN2jM8HF8=",
	},
	&CompatibilityTestFixture{
		TestName: "Fail to identify an unimplemented (oauth) signature",
		Request: &http.Request{
			Method: "POST",
			Body:   MakeBody("test content"),
			Header: MakeHeader(map[string][]string{
				"Authorization": []string{`OAuth oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog",oauth_nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",oauth_signature="tnnArxj06cWHq44gCs1OSKk%2FjLY%3D",oauth_signature_method="HMAC-SHA1",oauth_timestamp="1318622958",oauth_token="370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",oauth_version="1.0"`},
				"Content-Type":  []string{"text/plain"},
				"Date":          []string{"Fri, 19 Mar 1982 00:00:04 GMT"},
			}),
			URL: SilentURLParse("http://example.com/resource/1?key=value"),
		},
		SecretKey:  "secret-key",
		SystemTime: 1432075982,
		Digest:     sha1.New,
		Expected:   "", // Cannot identify
	},
}
