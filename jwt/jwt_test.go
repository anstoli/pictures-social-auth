package jwt

import (
	"io/ioutil"
	"log"
	"testing"
)

func TestEncode(t *testing.T) {
	const email = "a@b.com"
	tt, err := createTransformer()
	if err != nil {
		t.Fatal(err)
	}
	s, err := tt.Encode(&Data{Email: email})
	if err != nil {
		t.Fatal(err)
	}
	log.Printf("JWT: %s", s)
	d, err := tt.Decode(s)
	if err != nil {
		t.Fatal(err)
	}
	if d.Email != email {
		t.Errorf("Encrypted and decrypted emails don't match. Expected: %s got: %s", email, d.Email)
	}
}

func createTransformer() (*TokenTransformer, error) {
	pubKeyBytes, err := ioutil.ReadFile("test/jwk_sig_RS512_test.pub")
	if err != nil {
		return nil, err
	}
	privKeyBytes, err := ioutil.ReadFile("test/jwk_sig_RS512_test")
	if err != nil {
		return nil, err
	}
	return New(&Config{
		SigPublicKey:  pubKeyBytes,
		SigPrivateKey: privKeyBytes,
	})
}
