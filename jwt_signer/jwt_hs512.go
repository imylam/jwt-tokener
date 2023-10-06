package jwtsigner

import (
	"fmt"

	"github.com/imylam/crypto-utils/signature"
	"github.com/imylam/crypto-utils/signature/hs512"
	textcoder "github.com/imylam/text-coder"
)

func NewJwtHs512Signer(secret string) (signature.Signer, error) {
	secretDecoder := textcoder.Utf8Coder{}

	secretBytes, err := secretDecoder.Decode(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create JwtHs512Signer: %w", err)
	}

	return hs512.NewHS512(
		secretBytes,
		&textcoder.Utf8Coder{},
		&textcoder.Base64RawUrlCoder{},
	), nil
}

func NewJwtHs512Verifier(secret string) (signature.Verifier, error) {
	secretDecoder := textcoder.Utf8Coder{}

	secretBytes, err := secretDecoder.Decode(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create JwtHs512Signer: %w", err)
	}

	return hs512.NewHS512(
		secretBytes,
		&textcoder.Utf8Coder{},
		&textcoder.Base64RawUrlCoder{},
	), nil
}
