package httpapi

import (
	"net/http"
	"testing"
)

// 为什么：单用户监管形态对外只暴露 /v1/entities；内部 legacy tenant 路由必须
// 保持兼容，避免前后端与既有脚本在迁移期断裂。别名必须真的命中同一 handler，
// 而不是返回一个空壳 200。
func TestEntityAliasRoutes(t *testing.T) {
	srv, _ := newTestServer(t)

	resp, body := get(srv, "/v1/entities", "tok-admin")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/entities 期望 200，实际 %d body=%v", resp.StatusCode, body)
	}
	items, _ := body["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("entity 列表应复用 tenant 列表，期望 2 条，实际 %v", items)
	}

	resp2, body2 := get(srv, "/v1/entities/t-a/assets", "tok-admin")
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/entities/t-a/assets 期望 200，实际 %d body=%v", resp2.StatusCode, body2)
	}
	assets, _ := body2["items"].([]any)
	if len(assets) != 1 {
		t.Fatalf("entity 资产应复用 tenant 资产，期望 1 条，实际 %v", assets)
	}
}
