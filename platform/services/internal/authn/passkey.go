// passkey ES256 step-up（FR-TEN-005/AX-5）。
package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrPasskeyUnavailable = errors.New("authn: passkey unavailable")
	ErrPasskeyInvalid     = errors.New("authn: passkey invalid")
)

// Passkey 是 Phase 0 的 ES256 challenge-response step-up（非完整 WebAuthn）。
// 浏览器/客户端用私钥签名 challenge；服务端只存公钥。完整 WebAuthn
// （CBOR/COSE/attestation）作为 Provider 替换，接缝不变。
type Passkey struct {
	pub *ecdsa.PublicKey

	mu         sync.Mutex
	challenges map[string]time.Time
	stepups    map[string]time.Time
	ttl        time.Duration
}

// NewPasskey 接受 PEM 或 base64(PEM) 的 EC P-256 公钥。
func NewPasskey(publicKey string) (*Passkey, error) {
	raw := strings.TrimSpace(publicKey)
	if raw == "" {
		return nil, ErrPasskeyUnavailable
	}
	if !strings.Contains(raw, "BEGIN PUBLIC KEY") {
		if b, err := base64.StdEncoding.DecodeString(raw); err == nil {
			raw = string(b)
		}
	}
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("%w: PEM 解析失败", ErrPasskeyUnavailable)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPasskeyUnavailable, err)
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: 需要 EC P-256 公钥", ErrPasskeyUnavailable)
	}
	return &Passkey{
		pub:        pub,
		challenges: map[string]time.Time{},
		stepups:    map[string]time.Time{},
		ttl:        5 * time.Minute,
	}, nil
}

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Challenge 生成一次性 challenge（5 分钟）。
func (p *Passkey) Challenge() (string, error) {
	if p == nil {
		return "", ErrPasskeyUnavailable
	}
	c, err := randomB64(32)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	p.challenges[c] = time.Now().Add(p.ttl).UTC()
	p.mu.Unlock()
	return c, nil
}

// Verify 校验 challenge 签名并签发一次性 step-up token。
func (p *Passkey) Verify(challenge, signatureB64 string) (string, error) {
	if p == nil {
		return "", ErrPasskeyUnavailable
	}
	p.mu.Lock()
	exp, ok := p.challenges[challenge]
	delete(p.challenges, challenge) // 一次性：无论成功失败都消费
	p.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("%w: challenge 不存在或已使用", ErrPasskeyInvalid)
	}
	if !exp.After(time.Now().UTC()) {
		return "", fmt.Errorf("%w: challenge 已过期", ErrPasskeyInvalid)
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(signatureB64))
	if err != nil {
		return "", fmt.Errorf("%w: signature base64 非法", ErrPasskeyInvalid)
	}
	if !ecdsa.VerifyASN1(p.pub, []byte(challenge), sig) {
		return "", fmt.Errorf("%w: signature 不匹配", ErrPasskeyInvalid)
	}
	tok, err := randomB64(24)
	if err != nil {
		return "", err
	}
	p.mu.Lock()
	p.stepups[tok] = time.Now().Add(p.ttl).UTC()
	p.mu.Unlock()
	return tok, nil
}

// ValidateStepUp 校验 step-up token（不消费；有效期内可复用，确认动作本身仍一次性）。
func (p *Passkey) ValidateStepUp(token string) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	exp, ok := p.stepups[strings.TrimSpace(token)]
	if !ok {
		return false
	}
	if !exp.After(time.Now().UTC()) {
		delete(p.stepups, token)
		return false
	}
	return true
}

// GeneratePasskey 生成 P-256 密钥；privatePEM 仅离线保管，publicB64 写入 env。
func GeneratePasskey() (privatePEM, publicB64 string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	privatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}))
	publicB64 = base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
	return privatePEM, publicB64, nil
}
