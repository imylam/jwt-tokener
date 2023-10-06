package jwtsigner

import (
	"fmt"

	"github.com/imylam/crypto-utils/rsa"
	"github.com/imylam/crypto-utils/signature"
	"github.com/imylam/crypto-utils/signature/ps256"
	textcoder "github.com/imylam/text-coder"
)

func NewJwtPs256Signer(privateKeyPem string) (signature.Signer, error) {
	priKeyParser := rsa.Pkcs8PrivateKeyParser{}
	privateKey, err := priKeyParser.Parse(privateKeyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to create JwtPs256Signer: %w", err)
	}

	return ps256.NewSigner(
		privateKey,
		&textcoder.Utf8Coder{},
		&textcoder.Base64RawUrlCoder{},
	), nil
}

func NewJwtPs256Verifier(publicKeyPem string) (signature.Verifier, error) {
	pubKeyParser := rsa.PkixPublicKeyParser{}
	publicKey, err := pubKeyParser.Parse(publicKeyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to create JwtPs256Verifier: %w", err)
	}

	return ps256.NewVerifier(
		publicKey,
		&textcoder.Utf8Coder{},
		&textcoder.Base64RawUrlCoder{},
	), nil
}
