package httpapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/authn"
)

func TestPasskeyStepUpGatesPasskeyConfirmation(t *testing.T) {
	privPEM, pubB64, err := authn.GeneratePasskey()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := authn.NewPasskey(pubB64)
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := newConfirmTestServer(t, false, WithPasskey(pk))

	resp, body := post(t, srv.URL, "/v1/session/passkey/challenge", "tok-admin", "{}")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge 期望 200，实际 %d body=%s", resp.StatusCode, body)
	}
	var ch map[string]string
	if err := json.Unmarshal([]byte(body), &ch); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(privPEM))
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key.(*ecdsa.PrivateKey), []byte(ch["challenge"]))
	if err != nil {
		t.Fatal(err)
	}
	verifyBody, _ := json.Marshal(map[string]string{
		"challenge": ch["challenge"],
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	})
	resp2, body2 := post(t, srv.URL, "/v1/session/passkey/verify", "tok-admin", string(verifyBody))
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("verify 期望 200，实际 %d body=%s", resp2.StatusCode, body2)
	}
	var st map[string]string
	if err := json.Unmarshal([]byte(body2), &st); err != nil {
		t.Fatal(err)
	}

	confRaw, _ := json.Marshal(map[string]string{
		"entity_id": "t-a", "action": "scan.port", "resource": "example.com",
		"method": "passkey", "reason": "监管检查",
	})
	confBody := string(confRaw)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/confirmations", bytes.NewBufferString(confBody))
	req.Header.Set("Authorization", "Bearer tok-admin")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-EASM-StepUp", st["stepup_token"])
	resp3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusCreated {
		t.Fatalf("带 step-up 的确认期望 201，实际 %d", resp3.StatusCode)
	}

	resp4, body4 := post(t, srv.URL, "/v1/confirmations", "tok-admin", confBody)
	if resp4.StatusCode != http.StatusForbidden {
		t.Fatalf("缺 step-up 的 passkey 确认期望 403，实际 %d body=%s", resp4.StatusCode, body4)
	}
}
