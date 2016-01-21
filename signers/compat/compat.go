package compat

import (
	"crypto/sha256"
	signers "github.com/acquia/http-hmac-go/signers"
	"github.com/acquia/http-hmac-go/signers/v1"
	"github.com/acquia/http-hmac-go/signers/v2"
	"hash"
)

type SignatureIdentifier struct {
	compatSigners map[int]signers.Signer
}

func NewAllSignaturesIdentifier(digest func() hash.Hash) *SignatureIdentifier {
	return NewSignatureIdentifier(digest, 1, 2)
}

func NewSupportedSignatureIdentifier() *SignatureIdentifier {
	return NewSignatureIdentifier(sha256.New, 1, 2)
}

func NewSignatureIdentifier(digest func() hash.Hash, MinimumSupportedVersion int, MaximumSupportedVersion int) *SignatureIdentifier {
	inst := &SignatureIdentifier{
		compatSigners: map[int]signers.Signer{},
	}
	for version := MinimumSupportedVersion; version <= MaximumSupportedVersion; version++ {
		signer := inst.getNewInstanceByVersion(digest, version)
		if signer != nil {
			inst.compatSigners[version] = signer
		}
	}
	return inst
}

func (s *SignatureIdentifier) getNewInstanceByVersion(digest func() hash.Hash, version int) signers.Signer {
	switch version {
	case 1:
		sig, err := v1.NewV1Signer(digest)
		if err != nil {
			panic(err.Message)
		}
		return sig
	case 2:
		sig, err := v2.NewV2Signer(digest)
		if err != nil {
			panic(err.Message)
		}
		return sig
	default:
		return nil
	}
}

func (s *SignatureIdentifier) IdentifySignature(auth_header string) signers.Signer {
	for _, signer := range s.compatSigners {
		reg := signer.GetIdentificationRegex()
		if reg.MatchString(auth_header) {
			return signer
		}
	}
	return nil // incompatible signature
}

func (s *SignatureIdentifier) GetSigner(version int) signers.Signer {
	if signer, ok := s.compatSigners[version]; ok {
		return signer
	}
	return nil
}
