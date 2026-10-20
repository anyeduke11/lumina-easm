package authn

import (
	"context"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
)

func TestBreakGlassVerifyAndUse(t *testing.T) {
	token, hash, err := GenerateBreakGlass()
	if err != nil {
		t.Fatal(err)
	}
	l := &audit.MemLog{}
	bg, err := NewBreakGlass(hash, l)
	if err != nil {
		t.Fatal(err)
	}
	if !bg.Verify(token) {
		t.Fatal("正确 token 应通过")
	}
	if bg.Verify(token + "x") {
		t.Fatal("错误 token 不应通过")
	}
	bg.Use(context.Background(), "req-1")
	if len(l.Snapshot()) != 1 {
		t.Fatalf("使用应写审计，实际 %d", len(l.Snapshot()))
	}
	if _, err := NewBreakGlass("bad", l); err == nil {
		t.Fatal("非法 hash 应拒绝")
	}
}
