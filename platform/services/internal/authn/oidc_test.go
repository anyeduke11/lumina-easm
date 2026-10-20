package authn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func signJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	c, _ := json.Marshal(claims)
	input := b64u(h) + "." + b64u(c)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64u(sig)
}

func newOIDCTest(t *testing.T, key *rsa.PrivateKey) (*OIDC, *httptest.Server) {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": "k1",
			"n": b64u(key.PublicKey.N.Bytes()),
			"e": b64u(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}}})
	}))
	t.Cleanup(srv.Close)
	o, err := NewOIDC(srv.URL, "easm", srv.URL+"/jwks")
	if err != nil {
		t.Fatal(err)
	}
	return o, srv
}

func TestOIDCVerify(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	o, srv := newOIDCTest(t, key)
	tok := signJWT(t, key, "k1", map[string]any{
		"iss": srv.URL, "aud": "easm", "sub": "regulator-1",
		"exp": float64(time.Now().Add(time.Minute).Unix()),
	})
	p, err := o.Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if p.UserID != "regulator-1" || p.Role != "admin" {
		t.Fatalf("principal 不符: %+v", p)
	}
}

func TestOIDCRejectsExpiredAndAudience(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	o, srv := newOIDCTest(t, key)
	expired := signJWT(t, key, "k1", map[string]any{
		"iss": srv.URL, "aud": "easm", "sub": "u",
		"exp": float64(time.Now().Add(-time.Minute).Unix()),
	})
	if _, err := o.Verify(context.Background(), expired); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("过期 token 应拒绝，实际 %v", err)
	}
	wrongAud := signJWT(t, key, "k1", map[string]any{
		"iss": srv.URL, "aud": "other", "sub": "u",
		"exp": float64(time.Now().Add(time.Minute).Unix()),
	})
	if _, err := o.Verify(context.Background(), wrongAud); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("aud 不匹配应拒绝，实际 %v", err)
	}
}

func TestOIDCRejectsTamperedToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	o, srv := newOIDCTest(t, key)
	tok := signJWT(t, key, "k1", map[string]any{
		"iss": srv.URL, "aud": "easm", "sub": "u",
		"exp": float64(time.Now().Add(time.Minute).Unix()),
	})
	parts := strings.Split(tok, ".")
	evil, _ := json.Marshal(map[string]any{"iss": srv.URL, "aud": "easm", "sub": "evil", "exp": 9999999999})
	parts[1] = b64u(evil)
	if _, err := o.Verify(context.Background(), strings.Join(parts, ".")); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("篡改 token 应拒绝，实际 %v", err)
	}
}
