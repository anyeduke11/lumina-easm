package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

// 为什么（M2 前置 / 摄取面）：坏行入 unsupported 可复核（不静默丢）、越权行级拒、
// 写权限闸——端点语义必须与 candidate 包口径一致（C-6）。
func newCandServer(t *testing.T) *httptest.Server {
	t.Helper()
	l := &audit.MemLog{}
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"tok-tb":    {UserID: "u9", Role: "R1", TenantIDs: []string{"t-b"}},
		"tok-ro":    {UserID: "u3", Role: "R3", TenantIDs: []string{"*"}},
	}
	srv := httptest.NewServer(New(tenant.NewService(tenant.NewMemStore(), l),
		asset.NewService(asset.NewMemStore(), l), tokens,
		WithCandidates(candidate.NewService())).Handler())
	t.Cleanup(srv.Close)
	return srv
}

const goodLine = `{"kind":"finding","tenant_id":"t-a","sub_code":"SCAN-1","channel":"port.scan","finding":{"title":"t","category":"系统架构类","risk":"高"},"evidence":{"ts":"2026-10-17T00:00:00Z","raw_ref":"x#L1"}}`

func TestCandidateIngestEndpoints(t *testing.T) {
	srv := newCandServer(t)
	// 合法+非法混合：计数如实拆分，非整体拒绝
	resp, body := post(t, srv.URL, "/v1/candidates:ingest", "tok-admin", goodLine+"\nbad-json-line")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"accepted":1`) || !strings.Contains(body, `"unsupported":1`) {
		t.Fatalf("混合摄取计数错误: %d %s", resp.StatusCode, body)
	}
	// unsupported 可查且保留原文（复核锚点）
	resp, body = get2(srv.URL+"/v1/candidates/unsupported", "tok-admin")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "bad-json-line") {
		t.Errorf("unsupported 队列应含原始行: %d %s", resp.StatusCode, body)
	}
	// 越权租户：行级拒入 unsupported（不 403 整请求=批量部分成功语义）
	resp, body = post(t, srv.URL, "/v1/candidates:ingest", "tok-tb", goodLine)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"accepted":0`) || !strings.Contains(body, `"unsupported":1`) {
		t.Errorf("越权行应入 unsupported: %d %s", resp.StatusCode, body)
	}
	// 只读角色写 → 403
	if resp, _ = post(t, srv.URL, "/v1/candidates:ingest", "tok-ro", goodLine); resp.StatusCode != http.StatusForbidden {
		t.Errorf("只读角色摄取应 403，实际 %d", resp.StatusCode)
	}
}
