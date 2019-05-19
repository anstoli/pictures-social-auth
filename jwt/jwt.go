package jwt

import (
	"errors"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type TokenTransformer struct {
	sigPubKey jose.SigningKey
	signer jose.Signer
	sigPrivKey jose.SigningKey
}

type Config struct {
	SigPublicKey []byte
	SigPrivateKey []byte
}

type PicturesClaims struct {
	*jwt.Claims
	Email string
	CsrfTokenHash string
	Role string
}

func New(conf *Config) (*TokenTransformer, error) {
	tt := &TokenTransformer{}
	pubKey, err := loadKey(conf.SigPublicKey)
	if err != nil {
		return nil, err
	}
	tt.sigPubKey = jose.SigningKey{Algorithm: jose.RS512, Key: pubKey}

	privKey, err := loadKey(conf.SigPrivateKey)
	if err != nil {
		return nil, err
	}
	tt.sigPrivKey = jose.SigningKey{Algorithm: jose.RS512, Key: privKey}

	opts := (&jose.SignerOptions{}).WithType("JWT")

	tt.signer, err = jose.NewSigner(tt.sigPrivKey, opts)
	if err != nil {
		return nil, err
	}

	return tt, nil
}

func loadKey(json []byte) (*jose.JSONWebKey, error) {
	var jwk jose.JSONWebKey
	err := jwk.UnmarshalJSON(json)
	if err != nil {
		return nil, err
	}
	if !jwk.Valid() {
		return nil, errors.New("invalid JWK key")
	}
	return &jwk, nil
}

func (tt *TokenTransformer) Encode(c *PicturesClaims) (string, error) {
	builder := jwt.Signed(tt.signer)
	builder = builder.Claims(c)
	return builder.CompactSerialize()
}

func (tt *TokenTransformer) Decode(token string) (*PicturesClaims, error) {
	parsed, err := jwt.ParseSigned(token)
	// TODO: double check if alg should be checked manually to be not "none"
	if err != nil {
		return nil, err
	}
	c := &PicturesClaims{}
	err = parsed.Claims(tt.sigPubKey.Key, c)
	return c, err
}
