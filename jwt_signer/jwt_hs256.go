package jwtsigner

import (
	"fmt"

	"github.com/imylam/crypto-utils/signature"
	"github.com/imylam/crypto-utils/signature/hs256"
	textcoder "github.com/imylam/text-coder"
)

func NewJwtHs256Signer(secret string) (signature.Signer, error) {
	secretDecoder := textcoder.Utf8Coder{}

	secretBytes, err := secretDecoder.Decode(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create JwtHs256Signer: %w", err)
	}

	return hs256.NewHS256(
		secretBytes,
		&textcoder.Utf8Coder{},
		&textcoder.Base64RawUrlCoder{},
	), nil
}

func NewJwtHs256Verifier(secret string) (signature.Verifier, error) {
	secretDecoder := textcoder.Utf8Coder{}

	secretBytes, err := secretDecoder.Decode(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create JwtHs256Verifier: %w", err)
	}

	return hs256.NewHS256(
		secretBytes,
		&textcoder.Utf8Coder{},
		&textcoder.Base64RawUrlCoder{},
	), nil
}
