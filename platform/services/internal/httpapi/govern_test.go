package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
	"github.com/wangdev88/easm-platform/platform/services/internal/verifier"
)

func newGovernServer(t *testing.T) *httptest.Server {
	t.Helper()
	l := &audit.MemLog{}
	ctx := context.Background()
	ts := tenant.NewMemStore()
	_ = ts.Create(ctx, tenant.Tenant{ID: "t-a", Name: "甲", Status: "active"})
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
	}
	led := ledger.NewService(ledger.NewMemStore(), l)
	srv := httptest.NewServer(New(tenant.NewService(ts, l), asset.NewService(asset.NewMemStore(), l), tokens, WithLedger(led)).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, url, path, token, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url+path, bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

const goodLedger = `{"id":"L-2026-0001","phase":"P3","cat":"代码密码类","asset":"a.cn","title":"备份可下载","lv":"严重","src":"P3/Dirsearch","date":"2026-10-17T00:00:00Z","action":"删除","owner":"运维部","due":"2026-10-18T00:00:00Z"}`

// 为什么（FR-CLS / A-03）：detect 端点必须命中并解释（规则编号+片段）。
func TestClassifyDetectEndpoint(t *testing.T) {
	srv := newGovernServer(t)
	resp, body := post(t, srv.URL, "/v1/classify:detect", "tok-admin", `{"content":"-----BEGIN RSA PRIVATE KEY-----","input":{"ports":[6379]}}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", resp.StatusCode)
	}
	var out struct {
		Findings []struct {
			RuleID  string `json:"rule_id"`
			Snippet string `json:"snippet"`
		} `json:"findings"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	if len(out.Findings) < 2 {
		t.Fatalf("私钥+6379 应至少两条命中，实际: %s", body)
	}
	if !strings.Contains(body, "R-PRIVKEY") || !strings.Contains(body, "R-PORT") {
		t.Errorf("命中规则缺失: %s", body)
	}
}

// 为什么（A-07 / 一票否决③）：必填缺失端点必须 400。
func TestLedgerRequiredFieldsEndpoint(t *testing.T) {
	srv := newGovernServer(t)
	resp, _ := post(t, srv.URL, "/v1/tenants/t-a/ledger", "tok-admin", `{"id":"L-x","phase":"P9"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("非法条目期望 400，实际 %d", resp.StatusCode)
	}
	resp2, body2 := post(t, srv.URL, "/v1/tenants/t-a/ledger", "tok-admin", goodLedger)
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("完整条目期望 201，实际 %d %s", resp2.StatusCode, body2)
	}
}

// 为什么（FR-LGR-005）：未复测禁止闭环（422），复测器未接入返回 501 而非造假通过。
func TestLedgerClosedGatesEndpoint(t *testing.T) {
	srv := newGovernServer(t)
	_, _ = post(t, srv.URL, "/v1/tenants/t-a/ledger", "tok-admin", goodLedger)
	resp, _ := post(t, srv.URL, "/v1/ledger/L-2026-0001/actions", "tok-admin", `{"action":"closed"}`)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("直接闭环期望 422，实际 %d", resp.StatusCode)
	}
	// S-2 门3：sandbox 方法在未接入 provider 时 501（不拿「没有沙箱」冒充闭环）
	resp2, _ := post(t, srv.URL, "/v1/ledger/L-2026-0001/verify", "tok-admin", `{"method":"sandbox","result":"reproduced"}`)
	if resp2.StatusCode != http.StatusNotImplemented {
		t.Errorf("无沙箱 provider 时 sandbox 验证期望 501，实际 %d", resp2.StatusCode)
	}
	// 缺 body=400（不再把「空请求」当成复测请求）
	resp2b, _ := post(t, srv.URL, "/v1/ledger/L-2026-0001/verify", "tok-admin", `{}`)
	if resp2b.StatusCode != http.StatusBadRequest {
		t.Errorf("缺 method/result 期望 400，实际 %d", resp2b.StatusCode)
	}
	// reproduced 无证据引用=400（C-5：无可回溯主张不得闭环）
	resp2c, _ := post(t, srv.URL, "/v1/ledger/L-2026-0001/verify", "tok-admin", `{"method":"manual","result":"reproduced"}`)
	if resp2c.StatusCode != http.StatusBadRequest {
		t.Errorf("reproduced 无证据引用期望 400，实际 %d", resp2c.StatusCode)
	}
	// manual 复测+证据 → 200 且闭环
	resp2d, body2d := post(t, srv.URL, "/v1/ledger/L-2026-0001/verify", "tok-admin",
		`{"method":"manual","result":"reproduced","evidence_ref":"minio://easm-evidence/verify/x.json"}`)
	if resp2d.StatusCode != http.StatusOK || !strings.Contains(body2d, "reproduced") {
		t.Errorf("人工复测应 200+reproduced，实际 %d %s", resp2d.StatusCode, body2d)
	}
	// notify 走通（通报域动作在 M2 加审批门禁）
	resp3, body3 := post(t, srv.URL, "/v1/ledger/L-2026-0001/notify", "tok-admin", `{}`)
	if resp3.StatusCode != http.StatusOK || !strings.Contains(body3, "notice_id") {
		t.Errorf("通报标记期望 200+notice_id，实际 %d %s", resp3.StatusCode, body3)
	}
}

// 为什么（ENH-10 前端接缝装配，2026-10-18）：provider 在位时 method=sandbox 可用，
// 且**沙箱回执权威**——调用方声明（result=reproduced+假证据）被沙箱回执（refuted）覆盖，
// 不得透传调用方声明冒充闭环（与 ledger_test 的 TestSandboxVerifyRequiresProvider 同口径）。
func TestLedgerVerifySandboxProviderMounted(t *testing.T) {
	l := &audit.MemLog{}
	ctx := context.Background()
	ts := tenant.NewMemStore()
	_ = ts.Create(ctx, tenant.Tenant{ID: "t-a", Name: "甲", Status: "active"})
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
	}
	sbs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"result":"refuted","verifier":"sb-vm-1","note":"复现失败"}`))
	}))
	defer sbs.Close()
	sb, err := verifier.NewSandbox(sbs.URL)
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.NewService(ledger.NewMemStore(), l)
	led.SetVerifier(sb.VerifyItem) // 装配形态（main 同款）
	srv := httptest.NewServer(New(tenant.NewService(ts, l), asset.NewService(asset.NewMemStore(), l), tokens, WithLedger(led)).Handler())
	t.Cleanup(srv.Close)

	_, _ = post(t, srv.URL, "/v1/tenants/t-a/ledger", "tok-admin", goodLedger)
	resp, body := post(t, srv.URL, "/v1/ledger/L-2026-0001/verify", "tok-admin",
		`{"method":"sandbox","result":"reproduced","evidence_ref":"minio://fake/x.tar"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("沙箱 provider 在位应 200: %d %s", resp.StatusCode, body)
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(body), &out)
	if out["result"] != "refuted" || out["verifier"] != "sb-vm-1" {
		t.Errorf("provider 回执应权威覆盖调用方声明: %s", body)
	}
	_, body2 := get(srv, "/v1/ledger", "tok-admin")
	list := body2
	for _, it := range list["items"].([]any) {
		m := it.(map[string]any)
		if m["id"] == "L-2026-0001" && m["st"] == "closed" {
			t.Errorf("refuted 回执不得闭环: %v", body2)
		}
	}
}

func TestLedgerListCounts(t *testing.T) {
	srv := newGovernServer(t)
	_, _ = post(t, srv.URL, "/v1/tenants/t-a/ledger", "tok-admin", goodLedger)
	resp, body := get2(srv.URL+"/v1/ledger", "tok-admin")
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(body), &out)
	if out["total"].(float64) != 1 {
		t.Fatalf("total 期望 1: %s", body)
	}
	counts := out["counts"].(map[string]any)
	if counts["open"].(float64) != 1 {
		t.Errorf("open 计数期望 1: %v", counts)
	}
}

func get2(url, token string) (*http.Response, string) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	b := make([]byte, 8192)
	n, _ := resp.Body.Read(b)
	return resp, string(b[:n])
}
