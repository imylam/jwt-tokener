package jwttokener

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/imylam/crypto-utils/signature"
)

const (
	KEY_ALGO       string = "alg"
	KEY_TOKEN_TYPE string = "typ"
	TOKEN_TYPE     string = "JWT"

	ERR_DECODED_RAW_STR      string = "failed to decode raw string: "
	ERR_INVALID_TOKEN_FORMAT string = "format not valid"
	ERR_UNMARSAL_DECODED_STR string = "failed to unmarshal str to claims: "
	ERR_WRONG_HEADER_ALGO    string = "algo not matched"
	ERR_WRONG_HEADER_TYPE    string = "type is not JWT in header"
)

type Claims map[string]interface{}

type JwtTokener struct {
	signer   signature.Signer
	verifier signature.Verifier
}

func NewTokener(
	signer signature.Signer,
	verifier signature.Verifier,
) *JwtTokener {
	return &JwtTokener{
		signer:   signer,
		verifier: verifier,
	}
}

func (t *JwtTokener) Sign(payloadClaims Claims) (token string, err error) {
	headerClamis := Claims{
		KEY_ALGO:       t.signer.Algo(),
		KEY_TOKEN_TYPE: TOKEN_TYPE,
	}
	header, err := json.Marshal(headerClamis)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header claims: %w", err)
	}

	payload, err := json.Marshal(payloadClaims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal playload claims: %w", err)
	}

	b64Header := base64.RawURLEncoding.EncodeToString(header)
	b64Payload := base64.RawURLEncoding.EncodeToString(payload)

	sig, err := t.signer.Sign(b64Header + "." + b64Payload)
	if err != nil {
		err = fmt.Errorf("failed to sign token: %w", err)
		return
	}

	token = b64Header + "." + b64Payload + "." + sig

	return
}

func (t *JwtTokener) Verify(token string) (err error) {
	rawHeader, rawPayload, signature, err := getRawSegmentsFromToken(token)
	if err != nil {
		err = fmt.Errorf("failed to parse token: %w", err)
		return
	}

	err = t.verifyHeader(rawHeader)
	if err != nil {
		err = fmt.Errorf("failed to verify token: %w", err)
		return
	}

	err = t.verifier.Verify(rawHeader+"."+rawPayload, signature)
	if err != nil {
		err = fmt.Errorf("failed to verify token: %w", err)
		return
	}

	return
}

func (t *JwtTokener) GetPayloadClaims(
	token string,
) (payloadClaims Claims, err error) {
	_, rawPayload, _, err := getRawSegmentsFromToken(token)
	if err != nil {
		err = fmt.Errorf("failed to get payload claims: %w", err)
		return
	}

	payloadClaims, err = getClaimsFromRaw(rawPayload)
	if err != nil {
		err = fmt.Errorf("failed to get payload claims: %w", err)
		return
	}

	return
}

func (t *JwtTokener) verifyHeader(rawHeader string) (err error) {
	headerClaim, err := getClaimsFromRaw(rawHeader)
	if err != nil {
		return
	}

	if headerClaim[KEY_TOKEN_TYPE] != TOKEN_TYPE {
		err = errors.New(ERR_WRONG_HEADER_TYPE)
		return
	}

	if headerClaim[KEY_ALGO] != t.signer.Algo() {
		err = errors.New(ERR_WRONG_HEADER_ALGO)
		return
	}

	return
}

func getRawSegmentsFromToken(jwtToken string) (rawHeader, rawPayload, signature string, err error) {
	rawSegs := strings.Split(jwtToken, ".")

	if len(rawSegs) != 3 {
		err = errors.New(ERR_INVALID_TOKEN_FORMAT)
		return
	}

	rawHeader = rawSegs[0]
	rawPayload = rawSegs[1]
	signature = rawSegs[2]

	return
}

func getClaimsFromRaw(rawStr string) (claims Claims, err error) {
	decodeStr, err := base64.RawURLEncoding.DecodeString(rawStr)
	if err != nil {
		return
	}

	err = json.Unmarshal(decodeStr, &claims)
	if err != nil {
		return
	}

	return
}
