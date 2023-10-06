package jwtsigner

import (
	"fmt"

	"github.com/imylam/crypto-utils/rsa"
	"github.com/imylam/crypto-utils/signature"
	"github.com/imylam/crypto-utils/signature/rs512"
	textcoder "github.com/imylam/text-coder"
)

func NewJwtRs512Signer(privateKeyPem string) (signature.Signer, error) {
	priKeyParser := rsa.Pkcs8PrivateKeyParser{}
	privateKey, err := priKeyParser.Parse(privateKeyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to create JwtRs512Signer: %w", err)
	}

	return rs512.NewSigner(
		privateKey,
		&textcoder.Utf8Coder{},
		&textcoder.Base64RawUrlCoder{},
	), nil
}

func NewJwtRs512Verifier(publicKeyPem string) (signature.Verifier, error) {
	pubKeyParser := rsa.PkixPublicKeyParser{}
	publicKey, err := pubKeyParser.Parse(publicKeyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to create JwtRs512Verifier: %w", err)
	}

	return rs512.NewVerifier(
		publicKey,
		&textcoder.Utf8Coder{},
		&textcoder.Base64RawUrlCoder{},
	), nil
}
