package jwttokener

import (
	"testing"

	jwtsigner "github.com/imylam/jwt-tokener/jwt_signer"
	"github.com/stretchr/testify/assert"
)

const (
	Key        = "secret"
	PrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
dn/RsYEONbwQSjIfMPkvxF+8HQ==
-----END PRIVATE KEY-----`

	PublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`

	JWT_IO_HS256_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.ub7srKZNrlkC9jpqvPSYMwZp8IZQN1ZBCuld49qCqOs"
	JWT_IO_HS512_TOKEN = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.tKAtqOZxgyrxjs0GNb1rXpvCPda0exOFZXn3hDl22TkUreqeF0oT5bcwU6cDiztMDthAXZeBByAHNrofXRINIQ"
	JWT_IO_RS256_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.l1A63JJgwwLttEZRbAB5jx-iL0LxYNkJbSYU3BRFD76SaWhNjVYlZ3j1hKo8-06_nRGetYOGz0TkRZt2mJz-LstEjHZQpO4MSTvpiCrFGTTMP6cBZYeJr1PxGjUueCIagqSbH0yk1LUem_AtP4kPPjoO8Zv3OfWoYF5w3J1YxE2Phei3nrf6CUXfU5g_tqmjRvowaEh7s_ZnAb5IwEaq7lEKiA2pz76uMo0FFRBNxsBAxOeSfBQsZ4rHI2yUo5H_uj-7RSjV8JwmEbTn7gGaqlrSPlAE_OUv58z6evJbh9fBh8KZG8Eez4mPdoROMp-DaX5vZDaZGT0nO4tIFXceiA"
	JWT_IO_RS512_TOKEN = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.qYnwfkhBr54jBEONF850acvsOVmojp4WV_WGIRqJA4F3gNz-pHXqCBskm7XsRbA_tjcXt85jr5h3U2K1qmhAPBpLqSVu79loC-FIN5V5M-WZH8fGWguq0Q0fAVq1NkQ0XSUnN1aCdvVJmfbJxVlBPCjPUNj-Cm-0vkdj_lBZDyTb0Goz6w0bSl0ZgL-8PiPhrSGsHb9mCm0MJaAIcy0SJUzJGMbjnGM9kRPIhgCESnn1WXq3qy7uOLVGrMIfIQwEFqvVf1ByOJnIIjBQkskyelFJx2fkNaI0rdPWDeEODmWAsHcP733wgfXdfO_CWZIOMGrACiiA6yGwLszABjvKEQ"
	JWT_IO_PS256_TOKEN = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.rvXsAuOAFCkuRRTk7JtbcuTg31S56ezmQCMzAULD1KGykYGKioBOjqgWXQVUjl167RnhfS9VkdYyiql0XOjVuxyKLAjJ2qLeqtr1N_EHVfuy0bQd0XPzhGklaTGcJkx4r2dK_ToBQCZCBJynL7uc6Cnu1aBjjh6kvkc5bH1zOdj2_CYJAETW4KRx9AUFC2ndKSvaLAQcMFMfjnj_JFpt7-HlzjEfjFw1xKoZHfDp-_WcGERzO5NfwlFn8mN079on_UBaw6ORyGTLo14lV3tFjEnhdTw4nsvcgqJ2SIN5Wzi7Z6fLR4EdWNYyblHcrUu4QAPElrbzL4Wz7zAiEI7ABw"
	JWT_IO_PS512_TOKEN = "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.UG86HGSWo2beRx-TJ5RbcVps9fTfRS4C9HFOb9HQYdK6MzrkBlRQmhqlAJAmfjqDPRNIl2y-CmIRD8gAhpONEgunBOdYNDsB6j4pdRS9D9fNzE6vZ4fmuxsLK4CtdFuWGIUv9bWL9iJAbd-V705rFPmhdjWuRpexV9APh_ymkEnSDHDGgzn9SsOVUd0JhU1MIx5cspNUe7WmAP4kbXx31ZNHYZBH0vsPxSDoT4AhxNNb_hjGocrm1jX_3ytIO34iERdnmgRskdNBd69wbAfqyqb-7D4iKMIP4naD9ztqIvxHNF4ZQa1ixzf2dKsjjroOv91nriZkrWSQQ5wM876zJg"
)

var (
	hs256Signer, _   = jwtsigner.NewJwtHs256Signer(Key)
	hs256Verifier, _ = jwtsigner.NewJwtHs256Verifier(Key)
	hs512Signer, _   = jwtsigner.NewJwtHs512Signer(Key)
	hs512Verifier, _ = jwtsigner.NewJwtHs512Verifier(Key)
	rs256Signer, _   = jwtsigner.NewJwtRs256Signer(PrivateKey)
	rs256Verifier, _ = jwtsigner.NewJwtRs256Verifier(PublicKey)
	rs512Signer, _   = jwtsigner.NewJwtRs512Signer(PrivateKey)
	rs512Verifier, _ = jwtsigner.NewJwtRs512Verifier(PublicKey)
	ps256Signer, _   = jwtsigner.NewJwtPs256Signer(PrivateKey)
	ps256Verifier, _ = jwtsigner.NewJwtPs256Verifier(PublicKey)
	ps512Signer, _   = jwtsigner.NewJwtPs512Signer(PrivateKey)
	ps512Verifier, _ = jwtsigner.NewJwtPs512Verifier(PublicKey)

	hs256Tokener = NewTokener(hs256Signer, hs256Verifier)
	hs512Tokener = NewTokener(hs512Signer, hs512Verifier)
	rs256Tokener = NewTokener(rs256Signer, rs256Verifier)
	rs512Tokener = NewTokener(rs512Signer, rs512Verifier)
	ps256Tokener = NewTokener(ps256Signer, ps256Verifier)
	ps512Tokener = NewTokener(ps512Signer, ps512Verifier)

	payloadClaims = Claims{
		"iat":  float64(1516239022),
		"name": "John Doe",
		"sub":  "1234567890",
	}
)

func TestTokenerSignAgainstJwtIOResult(t *testing.T) {
	testCases := []struct {
		name    string
		tokener *JwtTokener
		want    string
	}{
		{
			name:    "HS256Tokener",
			tokener: hs256Tokener,
			want:    JWT_IO_HS256_TOKEN,
		},
		{
			name:    "HS512Tokener",
			tokener: hs512Tokener,
			want:    JWT_IO_HS512_TOKEN,
		},
		{
			name:    "RS256Tokener",
			tokener: rs256Tokener,
			want:    JWT_IO_RS256_TOKEN,
		},
		{
			name:    "RS512Tokener",
			tokener: rs512Tokener,
			want:    JWT_IO_RS512_TOKEN,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			token, err := tc.tokener.Sign(payloadClaims)

			assert.Nil(t, err)
			assert.Equal(t, tc.want, token)
		})
	}
}

func TestTokenerVerifyAgainstJwtIOResult(t *testing.T) {
	testCases := []struct {
		name    string
		tokener *JwtTokener
		token   string
	}{
		{
			name:    "HS256Tokener",
			tokener: hs256Tokener,
			token:   JWT_IO_HS256_TOKEN,
		},
		{
			name:    "HS512Tokener",
			tokener: hs512Tokener,
			token:   JWT_IO_HS512_TOKEN,
		},
		{
			name:    "RS256Tokener",
			tokener: rs256Tokener,
			token:   JWT_IO_RS256_TOKEN,
		},
		{
			name:    "RS512Tokener",
			tokener: rs512Tokener,
			token:   JWT_IO_RS512_TOKEN,
		},
		{
			name:    "PS256Tokener",
			tokener: ps256Tokener,
			token:   JWT_IO_PS256_TOKEN,
		},
		{
			name:    "PS512Tokener",
			tokener: ps512Tokener,
			token:   JWT_IO_PS512_TOKEN,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			err := tc.tokener.Verify(tc.token)

			assert.Nil(t, err)
		})
	}
}

func TestVerifyOwnSignedToken(t *testing.T) {
	testCases := []struct {
		name    string
		tokener *JwtTokener
	}{
		{
			name:    "HS256Tokener",
			tokener: hs256Tokener,
		},
		{
			name:    "HS512Tokener",
			tokener: hs512Tokener,
		},
		{
			name:    "RS256Tokener",
			tokener: rs256Tokener,
		},
		{
			name:    "RS512Tokener",
			tokener: rs512Tokener,
		},
		{
			name:    "PS256Tokener",
			tokener: ps256Tokener,
		},
		{
			name:    "PS512Tokener",
			tokener: ps512Tokener,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			token, err := tc.tokener.Sign(payloadClaims)
			assert.Nil(t, err)

			err = tc.tokener.Verify(token)
			assert.Nil(t, err)
		})
	}
}

func TestSignatureSignedByAnotherKeyShouldThrowError(t *testing.T) {
	JwtIoHS256Token2 := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.UY9JEV-Xuo95CR2L664Q8cb7eb-SHzvfhJsqJTmKAwI"
	JwtIoHS512Token2 := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.GHpYBLBUIfAWn6r-yeq7Z6BQMyuT7OU2_MyJw1Kccnarvf0_JBhc3VH_VeL-0RWGj_KCPEJZNEaueNxdLP3Psg"
	JwtIoRS256Token2 := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.h8k2a3LWVR1UgB_PmBMyyjTSCwL36-K2rC8kE0QAO0r6cFACUa7BhED9RJ0r0z-EtXTllm0TGmYJbwtfUWd0BpnMrOl2YgRKV0cbA-9gmi3nYluaGrugn6pK7aFP6nhBI9c4m29u57TgEkrweh3nRSwf5GOX7q_WuT1S0HOwLPwN9811ecc_Izm08JetDia-5hNq64TqMWvT2hrAz4KTHMxreILqESf8B9To06gSJEQTbt4udOfSRfe4ruED6LEif6Rq6K7nE-jmjoZZnjynCNhsk47NJ_aFNWJeTsIQkv2VXgyM55lb48GpF30m9nCXHj7aO1F4-ZwwpfLLX1cIrA"
	JwtIoRS512Token2 := "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.E1Xe_UKPm4C6Od3plE7IT0jhzkEgcle5DGDN6INdLwGIoD9YlVUCF_xTAnNmQJwUBNcxy1qSTGJ1ydTPOD2GoOk9f_CyT_Oxm4J-CKqc6SpB1q6PGOOIGFWzgS4tTITV-hfL0b4Ha3yhl_jdk5DOa2qAPpGgiLjjjtMFl_5YXnkmZYGD2ds899RYAOrqELH4jNRRUh9wdilL3NQ6bg6n_4q9kSbzYMy5iJqBYcrGP6b9UhRjrzfDxtO-zMBimyV0J-SuUQOKEgWt5WBZc1bp9aIjhREzx5qwD8MwwHGPi7CdMUio78doSB9nDlKwGcOPHPB22QBy5v96DmnjPvjadg"
	JwtIoPS256Token2 := "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.SPayLSDOrTUF0uJ1uKLeo19sevMZqf3Hk_zm3oclfchVqfFxj4g0k-b3nTAJ6S67G6eTN1Hfrxz91AT9WJd2jH_nmVZ_xD0Krc6u9TZhH8V-SaXoMhHOBIMFYFNf3svKfduG1GDaehv63ME38qj3tqNqo0gyYSp4anlIZABmx8N3gLeUhNuBI0czw-sGPBWwcLOEQ2dGiLlsVtTFRua4BlLVkV2f6ciBPZ5kzAgSNu7Awz3MQqT9wNNzfmxU8q06BYBzsSXBh_cOZ405JT1JhKes568vu0TLIyy_wPXeeu7KzBb_5tNlr0L9PLFZI-alTlFlmQ8nRdzYiUX0yeKpcg"
	JwtIoPS512Token2 := "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.DIAA2GcS1zVVXu32p_-bpQN0XuiKsgc9JuqCGipny9auDVq0hXvH-XAuBVUJH6SkCu_JdSKEJX_6dkvADzqH09FQOuBCxsKFm1jq9R3aHW8bdxA6GpaC3-NbMhNg60vEjtsXrFo456cg_WdR7b_qjBdSiqQWC4yX1wqBcRN--jfhKHtiyEz72MqQtMc5qkMqpWFZUGFhcSIcdSxF92RyIyfX9va2wsSwDhEa6ou-6cnHp6M8exADRUC4rx0p8XhN8XwXO9tEWywP1SFOX5CzanjKLQF1EqZDczA50hH5_ALZs2IUY3XbX0VsZbuC4lHTapEobyPb6BabayBSvRekRw"

	testCases := []struct {
		name    string
		token   string
		tokener *JwtTokener
	}{
		{
			name:    "HS256Tokener",
			token:   JwtIoHS256Token2,
			tokener: hs256Tokener,
		},
		{
			name:    "HS512Tokener",
			token:   JwtIoHS512Token2,
			tokener: hs512Tokener,
		},
		{
			name:    "RS256Tokener",
			token:   JwtIoRS256Token2,
			tokener: rs256Tokener,
		},
		{
			name:    "RS512Tokener",
			token:   JwtIoRS512Token2,
			tokener: rs512Tokener,
		},
		{
			name:    "PS256Tokener",
			token:   JwtIoPS256Token2,
			tokener: ps256Tokener,
		},
		{
			name:    "PS512Tokener",
			token:   JwtIoPS512Token2,
			tokener: ps512Tokener,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			err := tc.tokener.Verify(tc.token)

			expectedErrMsg := "failed to verify token:"
			assert.ErrorContainsf(
				t,
				err,
				expectedErrMsg,
				"expected error containing %q, got %s", expectedErrMsg, err,
			)
		})
	}
}

func TestGetPayloadClaims(t *testing.T) {
	payloadClaimsFromToken, _ := hs256Tokener.GetPayloadClaims(JWT_IO_HS256_TOKEN)

	assert.Equal(t, payloadClaims, payloadClaimsFromToken)
}

func TestWrongTokenFormatShouldThrowError(t *testing.T) {
	tokenWithoutSignature := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjIyI6Ik1pY3Jvc29mdCIsImdvbGFuZyI6Ikdvb2dsZSJ9"
	tokenWithHeaderOnly := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

	testCases := []struct {
		name    string
		tokener *JwtTokener
		token   string
	}{
		{
			name:    "GIVEN_token_without_signature_WHEN_verify_with_jwtHS256Tokener_THEN_return_error",
			tokener: hs256Tokener,
			token:   tokenWithoutSignature,
		},
		{
			name:    "GIVEN_token_with_header_only_WHEN_verify_with_jwtHS256Tokener_THEN_return_error",
			tokener: hs256Tokener,
			token:   tokenWithHeaderOnly,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			err := tc.tokener.Verify(tc.token)

			assert.Error(t, err)
		})
	}
}

func TestWrongTokenAlgoShouldThrowError(t *testing.T) {
	testCases := []struct {
		name    string
		tokener *JwtTokener
		token   string
	}{
		{
			name:    "GIVEN_token_with_HS512_Algo_WHEN_verify_with_jwtHS256Tokener_THEN_return_error",
			tokener: hs256Tokener,
			token:   JWT_IO_HS512_TOKEN,
		},
		{
			name:    "GIVEN_token_with_HS256_Algo_WHEN_verify_with_jwtHS512Tokener_THEN_return_error",
			tokener: hs512Tokener,
			token:   JWT_IO_HS256_TOKEN,
		},
		{
			name:    "GIVEN_token_with_HS256_Algo_WHEN_verify_with_jwtRS256Tokener_THEN_return_error",
			tokener: rs256Tokener,
			token:   JWT_IO_HS256_TOKEN,
		},
		{
			name:    "GIVEN_token_with_HS256_Algo_WHEN_verify_with_jwtRS512Tokener_THEN_return_error",
			tokener: rs512Tokener,
			token:   JWT_IO_HS256_TOKEN,
		},
		{
			name:    "GIVEN_token_with_HS256_Algo_WHEN_verify_with_jwtPS256Tokener_THEN_return_error",
			tokener: ps256Tokener,
			token:   JWT_IO_HS256_TOKEN,
		},
		{
			name:    "GIVEN_token_with_HS256_Algo_WHEN_verify_with_jwtPS512Tokener_THEN_return_error",
			tokener: ps512Tokener,
			token:   JWT_IO_HS256_TOKEN,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			err := tc.tokener.Verify(tc.token)

			assert.Error(t, err)
		})
	}
}
