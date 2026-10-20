package authn

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"
)

func TestPasskeyChallengeVerifyStepUp(t *testing.T) {
	privPEM, pubB64, err := GeneratePasskey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPasskey(pubB64)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(privPEM))
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	priv := key.(*ecdsa.PrivateKey)

	c, err := p.Challenge()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, priv, []byte(c))
	if err != nil {
		t.Fatal(err)
	}
	step, err := p.Verify(c, base64.RawURLEncoding.EncodeToString(sig))
	if err != nil {
		t.Fatal(err)
	}
	if !p.ValidateStepUp(step) {
		t.Fatal("step-up token 应有效")
	}
	if _, err := p.Verify(c, base64.RawURLEncoding.EncodeToString(sig)); !errors.Is(err, ErrPasskeyInvalid) {
		t.Fatalf("challenge 复用应拒绝，实际 %v", err)
	}
}

func TestPasskeyRejectsWrongSignature(t *testing.T) {
	_, pubB64, err := GeneratePasskey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPasskey(pubB64)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := p.Challenge()
	if _, err := p.Verify(c, base64.RawURLEncoding.EncodeToString([]byte("bad"))); !errors.Is(err, ErrPasskeyInvalid) {
		t.Fatalf("错误签名应拒绝，实际 %v", err)
	}
}
