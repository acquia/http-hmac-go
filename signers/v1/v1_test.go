package v1

import (
	"fmt"
	"github.com/acquia/http-hmac-go/signers"
	"testing"
)

var testVersion string = "v1"

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

func TestSign(t *testing.T) {
	evaluated := 0
	skipped := 0
	skipped_failure := 0
	passed := 0
	failed := 0

	for k, v := range signers.Fixtures {
		LogTest(t, "fixture ", k, " - ", v.TestName)
		if _, ok := v.Expected[testVersion]; !ok {
			if ert, ok := v.ErrorType[testVersion]; !ok || ert == signers.ErrorTypeNoError {
				LogSkip(t, "Skipping fixture", k, "- no v1 expected signature.")
				skipped++
				continue
			}
		}
		evaluated++
		signers.OverrideClock(v.SystemTime)
		signer, err := NewV1Signer(v.Digest)
		if err != nil {
			LogFail(t, "Failed to create signer:", err.Message)
			failed++
			t.Fail()
		} else {
			sig, err := signer.Sign(v.Request, v.AuthHeaders, v.SecretKey)
			if _, ok := v.ErrorType[testVersion]; !ok {
				v.ErrorType[testVersion] = signers.ErrorTypeNoError
			}
			if err != nil {
				if v.ErrorType[testVersion] == signers.ErrorTypeNoError {
					LogFail(t, "Failed to sign request:", err.Message)
					failed++
					t.Fail()
				} else {
					if err.ErrorType == v.ErrorType[testVersion] {
						LogPass(t, "Got expected error type", signers.GetErrorTypeText(v.ErrorType[testVersion]), "-", err.Message)
						passed++
					} else {
						LogFail(t, "Got error type", signers.GetErrorTypeText(err.ErrorType), "-", err.Message, "- but expected error type", signers.GetErrorTypeText(v.ErrorType[testVersion]))
						failed++
						t.Fail()
					}
				}
			} else {
				if v.ErrorType[testVersion] == signers.ErrorTypeNoError {
					if sig != v.Expected[testVersion] {
						t.Log("Expected signature:", v.Expected[testVersion])
						t.Log("Got signature:", sig)
						LogFail(t, "Signature mismatch.")
						t.Log("Was signing:\n" + string(signer.CreateSignable(v.Request, v.AuthHeaders)))
						failed++
						t.Fail()
					} else {
						LogPass(t, "Signature matches.")
						passed++

						if eh, ok := v.ExpectedHeader[testVersion]; ok {
							evaluated++
							LogTest(t, "fixture ", k, " Check() test")
							v.Request.Header.Set("Authorization", eh)
							if err := signer.Check(v.Request, v.SecretKey); err == nil {
								LogPass(t, "Signature check for Check passed.")
								passed++
							} else {
								LogFail(t, "Signature check for Check failed with error type ", signers.GetErrorTypeText(err.ErrorType))
								t.Log("Error message: ", err.Message)
								t.Log("Header being validated was ", eh)
								t.Fail()
								failed++
							}

							evaluated++
							LogTest(t, "fixture ", k, " SignDirect() test")
							err := signer.SignDirect(v.Request, v.AuthHeaders, v.SecretKey)
							if err != nil {
								LogFail(t, "Authorization header check for SignDirect failed with error type ", signers.GetErrorTypeText(err.ErrorType))
								t.Log("Error message: ", err.Message)
								failed++
							} else if v.Request.Header.Get("Authorization") == eh {
								LogPass(t, "Authorization header check for SignDirect passed.")
								passed++
							} else {
								LogFail(t, "Authorization header check for SignDirect failed with mismatch.")
								t.Log("Header expected was ", eh)
								t.Log("Header received was ", v.Request.Header.Get("Authorization"))
								t.Fail()
								failed++
							}

							evaluated++
							LogTest(t, "fixture ", k, " GenerateAuthorization() test")
							auth, err := signer.GenerateAuthorization(v.Request, v.AuthHeaders, sig)
							if err != nil {
								LogFail(t, "Authorization header check for GenerateAuthorization failed with error type ", signers.GetErrorTypeText(err.ErrorType))
								t.Log("Error message: ", err.Message)
								failed++
							} else if auth == eh {
								LogPass(t, "Authorization header check for GenerateAuthorization passed.")
								passed++
							} else {
								LogFail(t, "Authorization header check for GenerateAuthorization failed with mismatch.")
								t.Log("Header expected was ", eh)
								t.Log("Header received was ", auth)
								t.Fail()
								failed++
							}

						} else {
							LogSkip(t, "Skipping fixture ", k, " Check test: no expected authorization header provided for ", testVersion)
							skipped++
							LogSkip(t, "Skipping fixture ", k, " SignDirect test: no expected authorization header provided for ", testVersion)
							skipped++
							LogSkip(t, "Skipping fixture ", k, " GenerateAuthorization test: no expected authorization header provided for ", testVersion)
							skipped++
						}
					}
				} else {
					LogFail(t, "Got no error during signing but expected error type", signers.GetErrorTypeText(v.ErrorType[testVersion]))
					failed++
					t.Fail()
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
