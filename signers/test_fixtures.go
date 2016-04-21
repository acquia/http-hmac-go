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
	TestName       string
	Digest         func() hash.Hash
	Expected       map[string]string
	Request        *http.Request
	AuthHeaders    map[string]string
	SecretKey      string
	Response       *ResponseFixture
	SystemTime     int64
	ErrorType      map[string]ErrorType
	ExpectedHeader map[string]string
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
		TestName:   "v1 - simple GET request - invalid header in v2",
		SystemTime: 1432075982,
		Digest:     sha1.New,
		Expected: map[string]string{
			"v1": "7Tq3+JP3lAu4FoJz81XEx5+qfOc=",
		},
		Request: &http.Request{
			Method: "GET",
			URL:    SilentURLParse("http://example.com/resource/1?key=value"),
			Header: MakeHeader(map[string][]string{}),
		},
		AuthHeaders: map[string]string{
			"id": "efdde334-fe7b-11e4-a322-1697f925ec7b",
		},
		SecretKey: "secret-key",
		ErrorType: map[string]ErrorType{
			"v2": ErrorTypeInvalidAuthHeader,
		},
		ExpectedHeader: map[string]string{
			"v1": "Acquia efdde334-fe7b-11e4-a322-1697f925ec7b:7Tq3+JP3lAu4FoJz81XEx5+qfOc=",
		},
	},
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
		AuthHeaders: map[string]string{
			"id": "efdde334-fe7b-11e4-a322-1697f925ec7b",
		},
		SecretKey: "secret-key",
		ErrorType: map[string]ErrorType{
			"v2": ErrorTypeInvalidAuthHeader,
		},
		ExpectedHeader: map[string]string{
			"v1": "Acquia efdde334-fe7b-11e4-a322-1697f925ec7b:6DQcBYwaKdhRm/eNBKIN2jM8HF8=",
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
			"id":      "efdde334-fe7b-11e4-a322-1697f925ec7b",
		},
		SecretKey: "secret-key",
		ErrorType: map[string]ErrorType{
			"v2": ErrorTypeInvalidAuthHeader,
		},
		ExpectedHeader: map[string]string{},
	},
	&TestFixture{
		TestName:   "v2 - valid GET request 2",
		SystemTime: 1432075982,
		Digest:     sha256.New,
		Expected: map[string]string{
			"v2": "1Ku5UroiW1knVP6GH4l7Z4IuQSRxZO2gp/e5yhapv1s=",
		},
		Request: &http.Request{
			Method: "GET",
			Header: MakeHeader(map[string][]string{
				"X-Authorization-Timestamp": []string{"1432075982"},
			}),
			Host: "example.acquiapipet.net",
			URL:  SilentURLParse("https://example.acquiapipet.net/v1.0/task-status/145?limit=1"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Pipet service",
			"id":      "615d6517-1cea-4aa3-b48e-96d83c16c4dd",
			"nonce":   "24c0c836-4f6c-4ed6-a6b0-e091d75ea19d",
			"version": "2.0",
		},
		SecretKey: "TXkgU2VjcmV0IEtleSBUaGF0IGlzIFZlcnkgU2VjdXJl",
		Response: &ResponseFixture{
			Expected: map[string]string{
				"v2": "C98MEJHnQSNiYCxmI4CxJegO62sGZdzEEiSXgSIoxlo=",
			},
			Response: PrepareResponseWriter(`{"id": 145, "status": "in-progress"}`),
		},
		ErrorType: map[string]ErrorType{},
		ExpectedHeader: map[string]string{
			"v2": `acquia-http-hmac id="615d6517-1cea-4aa3-b48e-96d83c16c4dd",nonce="24c0c836-4f6c-4ed6-a6b0-e091d75ea19d",realm="Pipet%20service",signature="1Ku5UroiW1knVP6GH4l7Z4IuQSRxZO2gp/e5yhapv1s=",version="2.0"`,
		},
	},
	&TestFixture{
		TestName:   "v2 - valid GET request 3",
		SystemTime: 1432075982,
		Digest:     sha256.New,
		Expected: map[string]string{
			"v2": "yoHiYvx79ssSDIu3+OldpbFs8RsjrMXgRoM89d5t+zA=",
		},
		Request: &http.Request{
			Method: "GET",
			Header: MakeHeader(map[string][]string{
				"X-Authorization-Timestamp": []string{"1432075982"},
				"X-Custom-Signer1":          []string{"custom-1"},
				"X-Custom-Signer2":          []string{"custom-2"},
			}),
			Host: "example.pipeline.io",
			URL:  SilentURLParse("https://example.pipeline.io/api/v1/ci/pipelines"),
		},
		AuthHeaders: map[string]string{
			"realm":   "CIStore",
			"id":      "e7fe97fa-a0c8-4a42-ab8e-2c26d52df059",
			"nonce":   "a9938d07-d9f0-480c-b007-f1e956bcd027",
			"headers": "X-Custom-Signer1;X-Custom-Signer2",
			"version": "2.0",
		},
		SecretKey: "bXlzZWNyZXRzZWNyZXR0aGluZ3Rva2VlcA==",
		Response: &ResponseFixture{
			Expected: map[string]string{
				"v2": "cUDFSS5tN5vBBS7orIfUag8jhkaGouBb/o8fstUvTF8=",
			},
			Response: PrepareResponseWriter(`[{"pipeline_id":"39b5d58d-0a8f-437d-8dd6-4da50dcc87b7","sitename":"enterprise-g1:sfwiptravis","name":"pipeline.yml","last_job_id":"810e4344-1bed-4fd0-a642-1ba17eb996d5","last_branch":"validate-yaml","last_requested":"2016-03-25T20:26:39.000Z","last_finished":null,"last_status":"succeeded","last_duration":null}]`),
		},
		ErrorType: map[string]ErrorType{},
		ExpectedHeader: map[string]string{
			"v2": `acquia-http-hmac headers="X-Custom-Signer1%3BX-Custom-Signer2",id="e7fe97fa-a0c8-4a42-ab8e-2c26d52df059",nonce="a9938d07-d9f0-480c-b007-f1e956bcd027",realm="CIStore",signature="yoHiYvx79ssSDIu3+OldpbFs8RsjrMXgRoM89d5t+zA=",version="2.0"`,
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
			}),
			Host: "example.acquiapipet.net",
			URL:  SilentURLParse("https://example.acquiapipet.net/v1.0/task-status/133?limit=10"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Pipet service",
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
		ExpectedHeader: map[string]string{
			"v2": `acquia-http-hmac id="efdde334-fe7b-11e4-a322-1697f925ec7b",nonce="d1954337-5319-4821-8427-115542e08d10",realm="Pipet%20service",signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc=",version="2.0"`,
		},
	},
	&TestFixture{
		TestName:   "v2 - valid POST request",
		SystemTime: 1432075982,
		Digest:     sha256.New,
		Expected: map[string]string{
			"v2": "XDBaXgWFCY3aAgQvXyGXMbw9Vds2WPKJe2yP+1eXQgM=",
		},
		Request: &http.Request{
			Method:        "POST",
			Body:          MakeBody("{\"method\":\"hi.bob\",\"params\":[\"5\",\"4\",\"8\"]}"),
			ContentLength: int64(len("{\"method\":\"hi.bob\",\"params\":[\"5\",\"4\",\"8\"]}")),
			Header: MakeHeader(map[string][]string{
				"X-Authorization-Timestamp":      []string{"1432075982"},
				"X-Authorization-Content-SHA256": []string{"6paRNxUA7WawFxJpRp4cEixDjHq3jfIKX072k9slalo="},
				"Content-Type":                   []string{"application/json"},
			}),
			Host: "example.acquiapipet.net",
			URL:  SilentURLParse("https://example.acquiapipet.net/v1.0/task/"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Pipet service",
			"id":      "efdde334-fe7b-11e4-a322-1697f925ec7b",
			"nonce":   "d1954337-5319-4821-8427-115542e08d10",
			"version": "2.0",
		},
		SecretKey: "W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=",
		Response: &ResponseFixture{
			Expected: map[string]string{
				"v2": "LusIUHmqt9NOALrQ4N4MtXZEFE03MjcDjziK+vVqhvQ=",
			},
			Response: PrepareResponseWriter(``),
		},
		ErrorType: map[string]ErrorType{},
		ExpectedHeader: map[string]string{
			"v2": `acquia-http-hmac id="efdde334-fe7b-11e4-a322-1697f925ec7b",nonce="d1954337-5319-4821-8427-115542e08d10",realm="Pipet%20service",signature="XDBaXgWFCY3aAgQvXyGXMbw9Vds2WPKJe2yP+1eXQgM=",version="2.0"`,
		},
	},
	&TestFixture{
		TestName:   "v2 - valid POST request for register endpoint",
		SystemTime: 1449578521,
		Digest:     sha256.New,
		Expected: map[string]string{
			"v2": "4VtBHjqrdDeYrJySoJVDUHpN9u3vyTsyOLz4chezi98=",
		},
		Request: &http.Request{
			Method:        "POST",
			Body:          MakeBody("{\"method\":\"hi.bob\",\"params\":[\"5\",\"4\",\"8\"]}"),
			ContentLength: int64(len("{\"method\":\"hi.bob\",\"params\":[\"5\",\"4\",\"8\"]}")),
			Header: MakeHeader(map[string][]string{
				"X-Authorization-Timestamp":      []string{"1449578521"},
				"X-Authorization-Content-SHA256": []string{"6paRNxUA7WawFxJpRp4cEixDjHq3jfIKX072k9slalo="},
				"Content-Type":                   []string{"application/json"},
			}),
			Host: "54.154.147.142:3000",
			URL:  SilentURLParse("http://54.154.147.142:3000/register"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Plexus",
			"id":      "f0d16792-cdc9-4585-a5fd-bae3d898d8c5",
			"nonce":   "64d02132-40bf-4fce-85bf-3f1bb1bfe7dd",
			"version": "2.0",
		},
		SecretKey: "eox4TsBBPhpi737yMxpdBbr3sgg/DEC4m47VXO0B8qJLsbdMsmN47j/ZF/EFpyUKtAhm0OWXMGaAjRaho7/93Q==",
		ErrorType: map[string]ErrorType{},
		ExpectedHeader: map[string]string{
			"v2": `acquia-http-hmac id="f0d16792-cdc9-4585-a5fd-bae3d898d8c5",nonce="64d02132-40bf-4fce-85bf-3f1bb1bfe7dd",realm="Plexus",signature="4VtBHjqrdDeYrJySoJVDUHpN9u3vyTsyOLz4chezi98=",version="2.0"`,
		},
	},
	&TestFixture{
		TestName:   "v2 - valid POST request with signed headers",
		SystemTime: 1449578521,
		Digest:     sha256.New,
		Expected: map[string]string{
			"v2": "0duvqeMauat7pTULg3EgcSmBjrorrcRkGKxRDtZEa1c=",
		},
		Request: &http.Request{
			Method:        "POST",
			Body:          MakeBody(`{"cloud_endpoint":"https://cloudapi.acquia.com/v1","cloud_user":"example@acquia.com","cloud_pass":"password","branch":"validate"}`),
			ContentLength: int64(len(`{"cloud_endpoint":"https://cloudapi.acquia.com/v1","cloud_user":"example@acquia.com","cloud_pass":"password","branch":"validate"}`)),
			Header: MakeHeader(map[string][]string{
				"X-Authorization-Timestamp":      []string{"1449578521"},
				"X-Authorization-Content-SHA256": []string{"2YGTI4rcSnOEfd7hRwJzQ2OuJYqAf7jzyIdcBXCGreQ="},
				"Content-Type":                   []string{"application/json"},
				"X-Custom-Signer1":               []string{"custom-1"},
				"X-Custom-Signer2":               []string{"custom-2"},
			}),
			Host: "example.pipeline.io",
			URL:  SilentURLParse("https://example.pipeline.io/api/v1/ci/pipelines/39b5d58d-0a8f-437d-8dd6-4da50dcc87b7/start"),
		},
		AuthHeaders: map[string]string{
			"realm":   "CIStore",
			"id":      "e7fe97fa-a0c8-4a42-ab8e-2c26d52df059",
			"nonce":   "a9938d07-d9f0-480c-b007-f1e956bcd027",
			"headers": "X-Custom-Signer1;X-Custom-Signer2",
			"version": "2.0",
		},
		SecretKey: "bXlzZWNyZXRzZWNyZXR0aGluZ3Rva2VlcA==",
		Response: &ResponseFixture{
			Expected: map[string]string{
				"v2": "SlOYi3pUZADkzU9wEv7kw3hmxjlEyMqBONFEVd7iDbM=",
			},
			Response: PrepareResponseWriter(`"57674bb1-f2ce-4d0f-bfdc-736a78aa027a"`),
		},
		ErrorType: map[string]ErrorType{},
		ExpectedHeader: map[string]string{
			"v2": `acquia-http-hmac headers="X-Custom-Signer1%3BX-Custom-Signer2",id="e7fe97fa-a0c8-4a42-ab8e-2c26d52df059",nonce="a9938d07-d9f0-480c-b007-f1e956bcd027",realm="CIStore",signature="0duvqeMauat7pTULg3EgcSmBjrorrcRkGKxRDtZEa1c=",version="2.0"`,
		},
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
			}),
			Host: "example.acquiapipet.net",
			URL:  SilentURLParse("https://example.acquiapipet.net/v1.0/task/"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Pipet service",
			"id":      "efdde334-fe7b-11e4-a322-1697f925ec7b",
			"nonce":   "d1954337-5319-4821-8427-115542e08d10",
			"version": "2.0",
		},
		SecretKey: "W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=",
		ErrorType: map[string]ErrorType{
			"v2": ErrorTypeMissingRequiredHeader,
		},
		ExpectedHeader: map[string]string{},
	},
	/*&TestFixture{
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
			}),
			Host: "example.acquiapipet.net",
			URL:  SilentURLParse("https://example.acquiapipet.net/v1.0/task/"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Pipet service",
			"id":      "efdde334-fe7b-11e4-a322-1697f925ec7b",
			"nonce":   "d1954337-5319-4821-8427-115542e08d10",
			"version": "2.0",
		},
		SecretKey: "W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=",
		ErrorType: map[string]ErrorType{
			"v2": ErrorTypeMissingRequiredHeader,
		},
		ExpectedHeader: map[string]string{},
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
			}),
			Host: "example.acquiapipet.net",
			URL:  SilentURLParse("https://example.acquiapipet.net/v1.0/task/"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Pipet service",
			"id":      "efdde334-fe7b-11e4-a322-1697f925ec7b",
			"nonce":   "d1954337-5319-4821-8427-115542e08d10",
			"version": "2.0",
		},
		SecretKey: "W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=",
		ErrorType: map[string]ErrorType{
			"v2": ErrorTypeInvalidRequiredHeader,
		},
		ExpectedHeader: map[string]string{},
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
			}),
			Host: "example.acquiapipet.net",
			URL:  SilentURLParse("https://example.acquiapipet.net/v1.0/task/"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Pipet service",
			"id":      "efdde334-fe7b-11e4-a322-1697f925ec7b",
			"nonce":   "d1954337-5319-4821-8427-115542e08d10",
			"version": "2.0",
		},
		SecretKey: "W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=",
		ErrorType: map[string]ErrorType{
			"v2": ErrorTypeTimestampRangeError,
		},
		ExpectedHeader: map[string]string{},
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
			}),
			Host: "example.acquiapipet.net",
			URL:  SilentURLParse("https://example.acquiapipet.net/v1.0/task/"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Pipet service",
			"id":      "efdde334-fe7b-11e4-a322-1697f925ec7b",
			"nonce":   "d1954337-5319-4821-8427-115542e08d10",
			"version": "2.0",
		},
		SecretKey: "W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=",
		ErrorType: map[string]ErrorType{
			"v2": ErrorTypeTimestampRangeError,
		},
		ExpectedHeader: map[string]string{},
	},*/
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
			}),
			Host: "example.acquiapipet.net",
			URL:  SilentURLParse("https://example.acquiapipet.net/v1.0/task/"),
		},
		AuthHeaders: map[string]string{
			"realm":   "Pipet service",
			"id":      "efdde334-fe7b-11e4-a322-1697f925ec7b",
			"nonce":   "d1954337-5319-4821-8427-115542e08d10",
			"version": "2.0",
		},
		SecretKey: "this is a useless secret key for v2 authentication",
		ErrorType: map[string]ErrorType{
			"v2": ErrorTypeOutdatedKeypair,
		},
		ExpectedHeader: map[string]string{},
	},
}

var CompatFixtures []*CompatibilityTestFixture = []*CompatibilityTestFixture{
	&CompatibilityTestFixture{
		TestName: "Identify a v2 signature",
		Request: &http.Request{
			Method: "GET",
			Header: MakeHeader(map[string][]string{
				"X-Authorization-Timestamp": []string{"1432075982"},
				"Authorization":             []string{`acquia-http-hmac realm="Pipet%20service",id="efdde334-fe7b-11e4-a322-1697f925ec7b",nonce="d1954337-5319-4821-8427-115542e08d10",version="2.0",headers="",signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="`},
			}),
			Host: "example.acquiapipet.net",
			URL:  SilentURLParse("https://example.acquiapipet.net/v1.0/task-status/133?limit=10"),
		},
		SecretKey:  "W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=",
		SystemTime: 1432075982,
		Digest:     sha256.New,
		Expected:   "MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc=",
	},
	&CompatibilityTestFixture{
		TestName: "Identify a v1 signature",
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
