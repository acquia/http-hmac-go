package signers

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var Log *log.Logger

func Logf(format string, args ...interface{}) {
	if Log == nil {
		return
	}
	Log.Printf(format, args...)
}

func ReadBody(r *http.Request) ([]byte, error) {
	var data []byte = []byte{}
	if r.Body != nil {
		var err error
		data, err = ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		r.Body.Close()
		copy := data[:]
		r.Body = ioutil.NopCloser(bytes.NewReader(copy))
	}
	return data, nil
}

func ReadResponseBody(r *http.Response) ([]byte, error) {
	var data []byte = []byte{}
	if r.Body != nil {
		var err error
		data, err = ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		r.Body.Close()
		copy := data[:]
		r.Body = ioutil.NopCloser(bytes.NewReader(copy))
	}
	return data, nil
}

func Path(u *url.URL) string {
	return strings.TrimRight(fmt.Sprintf("/%s", strings.TrimLeft(u.Path, "/")), "/")
}

type Clock interface {
	Now() time.Time
}

type TestClock struct {
	Timestamp time.Time
}

func NewTestClock(timestamp int64) TestClock {
	return TestClock{
		Timestamp: time.Unix(timestamp, 0),
	}
}

func (t TestClock) Now() time.Time {
	return t.Timestamp
}

type RealClock struct{}

func (t RealClock) Now() time.Time {
	return time.Now()
}

var clock Clock = RealClock{}

func Now() time.Time {
	return clock.Now()
}

func OverrideClock(timestamp int64) {
	clock = NewTestClock(timestamp)
}
