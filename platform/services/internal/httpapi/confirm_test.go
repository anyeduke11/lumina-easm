package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/confirm"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

func newConfirmTestServer(t *testing.T, required bool, opts ...Option) (*httptest.Server, *confirm.Service) {
	t.Helper()
	l := &audit.MemLog{}
	tstore := tenant.NewMemStore()
	if err := tstore.Create(context.Background(), tenant.Tenant{ID: "t-a", Name: "A", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	cs := confirm.New(confirm.NewMemStore(), l)
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "admin", TenantIDs: []string{"*"}},
	}
	all := append([]Option{WithConfirmation(cs, required)}, opts...)
	srv := httptest.NewServer(New(
		tenant.NewService(tstore, l),
		asset.NewService(asset.NewMemStore(), l),
		tokens,
		all...,
	).Handler())
	t.Cleanup(srv.Close)
	return srv, cs
}

func TestConfirmationEndpointCreateAndGet(t *testing.T) {
	srv, _ := newConfirmTestServer(t, false)
	body := "{\"entity_id\":\"t-a\",\"action\":\"scan.port\",\"resource\":\"example.com\",\"method\":\"passkey\",\"reason\":\"监管检查通知\"}"
	resp, outText := post(t, srv.URL, "/v1/confirmations", "tok-admin", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("创建确认期望 201，实际 %d body=%s", resp.StatusCode, outText)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(outText), &out); err != nil {
		t.Fatalf("确认响应不是 JSON: %v body=%s", err, outText)
	}
	id, _ := out["id"].(string)
	if id == "" {
		t.Fatalf("确认缺少 id: %v", out)
	}
	resp2, out2 := get(srv, "/v1/confirmations/"+id, "tok-admin")
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("读取确认期望 200，实际 %d body=%v", resp2.StatusCode, out2)
	}
	if out2["entity_id"] != "t-a" || out2["action"] != "scan.port" {
		t.Fatalf("确认回读字段不符: %v", out2)
	}
}

func TestRequireConfirmationFailsLoudWithoutService(t *testing.T) {
	s := &Server{confirmRequired: true} // 闸开启但确认服务未装配=拒绝降级放行
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()
	if s.requireConfirmation(rr, req, "t-a", "scan.port", "example.com") {
		t.Fatal("确认服务缺失时不得放行")
	}
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("期望 501 fail loud，实际 %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestRequireConfirmationEnforcedAndSingleUse(t *testing.T) {
	_, cs := newConfirmTestServer(t, true)
	s := &Server{confirm: cs, confirmRequired: true}
	p := rbac.Principal{UserID: "u7", Role: "admin", TenantIDs: []string{"*"}}
	c, err := cs.Create(context.Background(), p, "req", confirm.Confirmation{
		EntityID: "t-a", Action: "scan.port", Resource: "example.com",
		Method: confirm.MethodPasskey, Reason: "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), keyPrincipal, p))
	rr := httptest.NewRecorder()
	if s.requireConfirmation(rr, req, "t-a", "scan.port", "example.com") {
		t.Fatal("缺确认头应拒绝")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("缺确认头期望 403，实际 %d body=%s", rr.Code, rr.Body.String())
	}

	req.Header.Set("X-EASM-Confirmation", c.ID)
	rr2 := httptest.NewRecorder()
	if !s.requireConfirmation(rr2, req, "t-a", "scan.port", "example.com") {
		t.Fatalf("有效确认应放行，实际 %d body=%s", rr2.Code, rr2.Body.String())
	}

	rr3 := httptest.NewRecorder()
	if s.requireConfirmation(rr3, req, "t-a", "scan.port", "example.com") {
		t.Fatal("确认复用应拒绝")
	}
	if rr3.Code != http.StatusConflict {
		t.Fatalf("确认复用期望 409，实际 %d body=%s", rr3.Code, rr3.Body.String())
	}
}
