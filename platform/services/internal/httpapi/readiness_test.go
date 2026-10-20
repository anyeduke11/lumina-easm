package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

// 为什么（可运营性）：/healthz 只证明进程活着；/readyz 必须回答「真实依赖是否可用」。
// 依赖故障返回 503 not_ready，且错误细节只进日志（不把 DSN/内部地址回执给调用方）。
func TestReadyz(t *testing.T) {
	l := &audit.MemLog{}
	tokens := map[string]rbac.Principal{"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}}}
	mk := func(opts ...Option) *httptest.Server {
		srv := httptest.NewServer(New(
			tenant.NewService(tenant.NewMemStore(), l),
			asset.NewService(asset.NewMemStore(), l),
			tokens, opts...,
		).Handler())
		t.Cleanup(srv.Close)
		return srv
	}

	okSrv := mk()
	resp, body := get(okSrv, "/readyz", "")
	if resp.StatusCode != http.StatusOK || body["status"] != "ready" {
		t.Fatalf("无外部依赖应 ready: %d %v", resp.StatusCode, body)
	}

	down := mk(WithReady(func(context.Context) error { return errors.New("dial tcp 10.0.0.5:5432: refused") }))
	resp, body = get(down, "/readyz", "")
	e, _ := body["error"].(map[string]any)
	if resp.StatusCode != http.StatusServiceUnavailable || e["code"] != "not_ready" {
		t.Fatalf("依赖故障应 503 not_ready: %d %v", resp.StatusCode, body)
	}
	if msg, _ := e["message"].(string); strings.Contains(msg, "10.0.0.5") || strings.Contains(msg, "5432") {
		t.Errorf("就绪回执不得泄露依赖地址/端口: %q", msg)
	}
}

// 为什么（可用性）：单请求 panic 不得拖垮进程，也不得把堆栈泄露给调用方；
// 必须返回统一错误体 500 internal，便于前端与审计按 request_id 对齐。
func TestRecoverPanicReturnsInternal(t *testing.T) {
	h := recoverPanic(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom-secret-detail")
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/whatever", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("panic 应 500，实际 %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"code":"internal"`) || !strings.Contains(body, `"request_id"`) {
		t.Errorf("错误体应为统一 internal 结构: %s", body)
	}
	if strings.Contains(body, "boom-secret-detail") || strings.Contains(body, "goroutine") {
		t.Errorf("回执泄露 panic 详情/堆栈: %s", body)
	}
}
