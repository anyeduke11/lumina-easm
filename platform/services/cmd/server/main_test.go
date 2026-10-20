package main

import (
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

func TestSingleUserTokensRequiresExactlyOne(t *testing.T) {
	if _, err := singleUserTokens(nil); err == nil {
		t.Fatal("空令牌表应拒绝")
	}
	if _, err := singleUserTokens(map[string]rbac.Principal{
		"a": {UserID: "a", Role: "R1"},
		"b": {UserID: "b", Role: "R2"},
	}); err == nil {
		t.Fatal("多枚令牌应拒绝（单用户模式不暴露多账号）")
	}
}

func TestSingleUserTokensForcesAdmin(t *testing.T) {
	got, err := singleUserTokens(map[string]rbac.Principal{
		"tok": {UserID: "dev-tok", Role: "R1", TenantIDs: []string{"t-a"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := got["tok"]
	if p.Role != "admin" {
		t.Fatalf("角色应为 admin，实际 %q", p.Role)
	}
	if len(p.TenantIDs) != 1 || p.TenantIDs[0] != "*" {
		t.Fatalf("entity scope 应重置为 *，实际 %v", p.TenantIDs)
	}
}
