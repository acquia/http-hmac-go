package compat

import (
	"fmt"
	"github.com/acquia/http-hmac-go/signers"
	"github.com/acquia/http-hmac-go/signers/v1"
	"github.com/acquia/http-hmac-go/signers/v2"
	"testing"
)

func LogTest(t *testing.T, args ...interface{}) {
	t.Log("\033[34;1mTEST\033[0m", fmt.Sprint(args...))
}

func LogFail(t *testing.T, args ...interface{}) {
	t.Log("\033[31;1mFAIL\033[0m", fmt.Sprint(args...))
}

func LogPass(t *testing.T, args ...interface{}) {
	t.Log("\033[32;1mPASS\033[0m", fmt.Sprint(args...))
}

func LogSkip(t *testing.T, args ...interface{}) {
	t.Log("\033[33;1mSKIP\033[0m", fmt.Sprint(args...))
}

func TestIdentifyAndSign(t *testing.T) {
	evaluated := 0
	skipped := 0
	skipped_failure := 0
	passed := 0
	failed := 0

	for k, v := range signers.CompatFixtures {
		evaluated++
		LogTest(t, "fixture ", k, " - ", v.TestName)
		signers.OverrideClock(v.SystemTime)
		ident := NewAllSignaturesIdentifier(v.Digest)
		signer := ident.IdentifySignature(v.Request.Header.Get("Authorization"))
		if signer == nil {
			if v.Expected != "" {
				t.Log("Authorization:", v.Request.Header.Get("Authorization"))
				t.Log("Couldn't find signer matching signature for fixture.")
				LogFail(t, "We were supposed to find a signer, as expected signature is", v.Expected)
				failed++
				t.Fail()
			} else {
				LogPass(t, "We were expecting no signature and found no matching signer.")
				passed++
			}
		} else {
			if v.Expected == "" {
				t.Log("Authorization:", v.Request.Header.Get("Authorization"))
				t.Log("Found a signer matching the fixture.")
				LogFail(t, "Expected no signature, we were not supposed to match any signer.")
				failed++
				t.Fail()
			} else {
				sig, err := signer.Sign(v.Request, signer.ParseAuthHeaders(v.Request), v.SecretKey)
				if err != nil {
					LogFail(t, "Could not sign request due to error: ", err.Message)
					failed++
					t.Fail()
				} else {
					if sig != v.Expected {
						t.Log("Expected signature:", v.Expected)
						t.Log("Got signature:", sig)
						if s, ok := signer.(*v1.V1Signer); ok {
							t.Log("Was signing:\n" + string(s.CreateSignable(v.Request, signer.ParseAuthHeaders(v.Request))))
						}
						if s, ok := signer.(*v2.V2Signer); ok {
							hb, _ := s.HashBody(v.Request)
							t.Log("Was signing:\n" + string(s.CreateSignable(v.Request, signer.ParseAuthHeaders(v.Request), hb)))
						}
						LogFail(t, "Signature mismatch.")
						failed++
						t.Fail()
					} else {
						LogPass(t, "Signature matches.")
						passed++
					}
				}
			}
		}
	}

	t.Log("")
	t.Log("Test results:")
	t.Logf("%d \033[34mexpectations evaluated.\033[0m", evaluated)
	t.Logf("%d \033[32mexpectations met.\033[0m", passed)
	t.Logf("%d \033[31mexpectations not met.\033[0m", failed)
	t.Logf("%d \033[33mpotential expectations skipped.\033[0m", skipped)
	if failed > 0 {
		t.Logf("(%d skipped expectations \033[31mnever evaluated due to failure.\033[0m)", skipped_failure)
	}
	if failed > 0 {
		t.Log("Conclusion: test FAILED.")
	} else {
		t.Log("Conclusion: test PASSED.")
	}
}
