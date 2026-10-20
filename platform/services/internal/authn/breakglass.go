// break-glass 应急凭据（FR-TEN-005/CR-001/AX-5）。
package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
)

// BreakGlass 是预置的应急凭据：env 只存 SHA-256，明文离线保管。
// 每次使用都写 audit；轮换=生成新 token/hash 并重启。
type BreakGlass struct {
	hash []byte
	log  audit.Log
}

func NewBreakGlass(hashHex string, log audit.Log) (*BreakGlass, error) {
	h, err := hex.DecodeString(strings.TrimSpace(hashHex))
	if err != nil || len(h) != sha256.Size {
		return nil, fmt.Errorf("authn: EASM_BREAKGLASS_HASH 须为 64 位 hex（SHA-256）")
	}
	return &BreakGlass{hash: h, log: log}, nil
}

func (b *BreakGlass) Verify(token string) bool {
	if b == nil || strings.TrimSpace(token) == "" {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(sum[:], b.hash) == 1
}

func (b *BreakGlass) Use(ctx context.Context, reqID string) {
	if b == nil || b.log == nil {
		return
	}
	_ = b.log.Append(ctx, audit.Entry{
		Actor: "breakglass", Action: "breakglass.use", Resource: "admin",
		Result: audit.ResultAllow, RequestID: reqID,
	})
}

// GenerateBreakGlass 生成一次性展示的应急 token 与可入库的 hash。
func GenerateBreakGlass() (token, hashHex string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = "BG-" + hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}
