// Package authn 提供 OIDC / 应急凭据 / passkey 的认证接缝（FR-TEN-005/NFR-SEC-002/AX-5）。
package authn

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

var (
	ErrUnauthenticated = errors.New("authn: unauthenticated")
	ErrTokenExpired    = errors.New("authn: token expired")
	ErrTokenInvalid    = errors.New("authn: token invalid")
)

// OIDC 校验 RS256 access token（JWKS 公钥；iss/aud/exp/nbf）。
type OIDC struct {
	issuer   string
	audience string
	jwksURL  string
	hc       *http.Client

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
	ttl     time.Duration
}

// NewOIDC 创建校验器；三个参数必须同时给出（fail loud）。
func NewOIDC(issuer, audience, jwksURL string) (*OIDC, error) {
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(audience) == "" || strings.TrimSpace(jwksURL) == "" {
		return nil, fmt.Errorf("authn: OIDC issuer/audience/jwks_url 必须同设")
	}
	return &OIDC{
		issuer: issuer, audience: audience, jwksURL: jwksURL,
		hc:   &http.Client{Timeout: 10 * time.Second},
		ttl:  5 * time.Minute,
		keys: map[string]*rsa.PublicKey{},
	}, nil
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func jsonMap(b []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// Verify 校验 JWT 并映射为单用户 admin 主体。
func (o *OIDC) Verify(ctx context.Context, token string) (rbac.Principal, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return rbac.Principal{}, ErrUnauthenticated
	}
	hb, err := b64(parts[0])
	if err != nil {
		return rbac.Principal{}, ErrUnauthenticated
	}
	h, err := jsonMap(hb)
	if err != nil {
		return rbac.Principal{}, ErrUnauthenticated
	}
	alg, _ := h["alg"].(string)
	if alg != "RS256" {
		return rbac.Principal{}, fmt.Errorf("%w: 仅支持 RS256", ErrTokenInvalid)
	}
	kid, _ := h["kid"].(string)
	pub, err := o.key(ctx, kid)
	if err != nil {
		return rbac.Principal{}, err
	}
	sig, err := b64(parts[2])
	if err != nil {
		return rbac.Principal{}, ErrUnauthenticated
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return rbac.Principal{}, ErrUnauthenticated
	}
	pb, err := b64(parts[1])
	if err != nil {
		return rbac.Principal{}, ErrUnauthenticated
	}
	c, err := jsonMap(pb)
	if err != nil {
		return rbac.Principal{}, ErrUnauthenticated
	}
	now := float64(time.Now().Unix())
	if iss, _ := c["iss"].(string); iss != o.issuer {
		return rbac.Principal{}, fmt.Errorf("%w: issuer 不匹配", ErrTokenInvalid)
	}
	if !audienceOK(c["aud"], o.audience) {
		return rbac.Principal{}, fmt.Errorf("%w: audience 不匹配", ErrTokenInvalid)
	}
	if exp, ok := c["exp"].(float64); !ok || exp <= now {
		return rbac.Principal{}, ErrTokenExpired
	}
	if nbf, ok := c["nbf"].(float64); ok && nbf > now {
		return rbac.Principal{}, fmt.Errorf("%w: token 尚未生效", ErrTokenInvalid)
	}
	sub, _ := c["sub"].(string)
	if strings.TrimSpace(sub) == "" {
		return rbac.Principal{}, fmt.Errorf("%w: sub 缺失", ErrTokenInvalid)
	}
	role := "admin"
	if r, ok := c["role"].(string); ok && r != "" {
		role = r
	}
	return rbac.Principal{UserID: sub, Role: role, TenantIDs: []string{"*"}}, nil
}

func audienceOK(v any, want string) bool {
	switch x := v.(type) {
	case string:
		return x == want
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func (o *OIDC) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.keys) == 0 || time.Since(o.fetched) > o.ttl {
		if err := o.fetch(ctx); err != nil {
			return nil, err
		}
	}
	if kid != "" {
		if k, ok := o.keys[kid]; ok {
			return k, nil
		}
	}
	for _, k := range o.keys {
		return k, nil
	}
	return nil, fmt.Errorf("%w: 无可用 JWKS 公钥", ErrTokenInvalid)
}

func (o *OIDC) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := o.hc.Do(req)
	if err != nil {
		return fmt.Errorf("authn: 获取 JWKS 失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authn: JWKS 返回 %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("authn: JWKS 解析失败: %w", err)
	}
	raw, _ := doc["keys"].([]any)
	keys := map[string]*rsa.PublicKey{}
	for _, item := range raw {
		m, _ := item.(map[string]any)
		kty, _ := m["kty"].(string)
		if kty != "RSA" {
			continue
		}
		kid, _ := m["kid"].(string)
		ns, _ := m["n"].(string)
		es, _ := m["e"].(string)
		nb, err1 := b64(ns)
		eb, err2 := b64(es)
		if err1 != nil || err2 != nil || len(nb) == 0 || len(eb) == 0 {
			continue
		}
		e := 0
		for _, b := range eb {
			e = e<<8 | int(b)
		}
		keys[kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
	}
	if len(keys) == 0 {
		return fmt.Errorf("authn: JWKS 无 RSA 公钥")
	}
	o.keys = keys
	o.fetched = time.Now()
	return nil
}
