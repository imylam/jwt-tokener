package jwtsigner

import (
	"fmt"

	"github.com/imylam/crypto-utils/rsa"
	"github.com/imylam/crypto-utils/signature"
	"github.com/imylam/crypto-utils/signature/rs256"
	textcoder "github.com/imylam/text-coder"
)

func NewJwtRs256Signer(privateKeyPem string) (signature.Signer, error) {
	priKeyParser := rsa.Pkcs8PrivateKeyParser{}
	privateKey, err := priKeyParser.Parse(privateKeyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to create JwtRs256Signer: %w", err)
	}

	return rs256.NewSigner(
		privateKey,
		&textcoder.Utf8Coder{},
		&textcoder.Base64RawUrlCoder{},
	), nil
}

func NewJwtRs256Verifier(publicKeyPem string) (signature.Verifier, error) {
	pubKeyParser := rsa.PkixPublicKeyParser{}
	publicKey, err := pubKeyParser.Parse(publicKeyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to create JwtRs256Verifier: %w", err)
	}

	return rs256.NewVerifier(
		publicKey,
		&textcoder.Utf8Coder{},
		&textcoder.Base64RawUrlCoder{},
	), nil
}
