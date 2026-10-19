package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/authz"
	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
	"github.com/wangdev88/easm-platform/platform/services/internal/darkweb"
	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

// 为什么（M2-02 对外可观测面）：暗网巡检全链必须经 REST 端到端可用且受三重闸约束——
// 归属样本出线索包（含量级区间+证据 ref）、无授权总闸=403 no_valid_scope、越权租户=403、
// 无写权限=403、无指纹基线=归属 0 且不出包。端点是「巡检能否真的用于通报」的第一现场。
func newDarkServer(t *testing.T) (*httptest.Server, *ownership.Service, *authz.Service) {
	t.Helper()
	l := &audit.MemLog{}
	tsvc := tenant.NewService(tenant.NewMemStore(), l)
	led := ledger.NewService(ledger.NewMemStore(), l)
	az := authz.NewService(authz.NewMemStore(), l)
	cands := candidate.NewService()
	own := ownership.NewService()
	ev, err := evidence.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dark := darkweb.New(cands, led, az, own, ev)
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"tok-ops":   {UserID: "u1", Role: "R1", TenantIDs: []string{"t-a"}},
		"tok-ro":    {UserID: "u3", Role: "R3", TenantIDs: []string{"*"}},
	}
	srv := httptest.NewServer(New(tsvc, asset.NewService(asset.NewMemStore(), l), tokens,
		WithAuthz(az), WithLedger(led), WithCandidates(cands), WithKnowledge(nil, nil, own), WithDarkweb(dark)).Handler())
	t.Cleanup(srv.Close)
	return srv, own, az
}

func ownedSampleJSON(id string) string {
	return `{"id":"` + id + `","domain":"` + id + `.onion","marketplace":"暗市","post_url":"http://` + id + `.onion/p","captured_at":"2026-10-17T00:00:00Z","raw_text":"样本 ` + id + `","cert_fingerprint":"AA:BB:CC","sample_records":100,"id_min":1,"id_max":5000}`
}

func TestDarkwebInspectEndpoint(t *testing.T) {
	srv, own, az := newDarkServer(t)
	post(t, srv.URL, "/v1/tenants", "tok-admin", `{"id":"t-d","name":"暗网公司","short":"暗网","root_domains":["d.cn"]}`)
	own.SetFingerprints(context.Background(), "t-d", ownership.Fingerprints{CertFPs: []string{"AA:BB:CC"}})
	if err := az.Upsert(context.Background(), rbac.Principal{UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"r", authz.Scope{Tenant: "t-d", Domains: []string{"d.cn"}, ValidFrom: time.Now().Add(-time.Hour), ValidTo: time.Now().Add(time.Hour), Signer: "s", DocHash: "h"}); err != nil {
		t.Fatal(err)
	}

	// ① 归属样本 → 200 + 线索包（content_hash + evidence_ref + 区间规模）
	resp, body := post(t, srv.URL, "/v1/tenants/t-d/darkweb:inspect", "tok-admin", `{"samples":[`+ownedSampleJSON("S1")+`, `+ownedSampleJSON("S2")+`]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("巡检期望 200，实际 %d %s", resp.StatusCode, body)
	}
	var res darkweb.Result
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if res.Owned != 2 || res.PackageID == "" || res.ContentHash == "" {
		t.Errorf("归属样本应出线索包: %+v", res)
	}
	if !strings.HasPrefix(res.EvidenceRef, "file://") {
		t.Errorf("线索包应固化证据: %q", res.EvidenceRef)
	}
	if res.Scale.High <= res.Scale.Low {
		t.Errorf("量级须为区间（FR-CHN-006）: %+v", res.Scale)
	}

	// ①b 落库/内存可检索面：list 含刚出的包，get 取回整包取证要素齐备；跨租户 get=404
	_, lb := get2(srv.URL+"/v1/tenants/t-d/darkweb/packages", "tok-admin")
	if !strings.Contains(lb, res.PackageID) {
		t.Errorf("包列表应含新包 %s: %s", res.PackageID, lb)
	}
	respG, gb := get2(srv.URL+"/v1/tenants/t-d/darkweb/packages/"+res.PackageID, "tok-admin")
	if respG.StatusCode != http.StatusOK || !strings.Contains(gb, "sample_hash") || !strings.Contains(gb, "captured_at") {
		t.Errorf("取回整包须含取证要素: %d %s", respG.StatusCode, gb[:min(300, len(gb))])
	}
	respG, _ = get2(srv.URL+"/v1/tenants/t-d/darkweb/packages/"+res.PackageID, "tok-ops") // 只见 t-a
	if respG.StatusCode != http.StatusForbidden {
		t.Errorf("越权主体读包期望 403，实际 %d", respG.StatusCode)
	}

	// ② 越权租户（tok-ops 仅 t-a）→ 403
	resp, _ = post(t, srv.URL, "/v1/tenants/t-d/darkweb:inspect", "tok-ops", `{"samples":[`+ownedSampleJSON("S1")+`]}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("越权巡检期望 403，实际 %d", resp.StatusCode)
	}

	// ③ 无写权限（tok-ro）→ 403
	resp, _ = post(t, srv.URL, "/v1/tenants/t-d/darkweb:inspect", "tok-ro", `{"samples":[`+ownedSampleJSON("S1")+`]}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("无写权限期望 403，实际 %d", resp.StatusCode)
	}

	// ④ 无授权总闸（t-none 未 upsert scope）→ 403 no_valid_scope
	post(t, srv.URL, "/v1/tenants", "tok-admin", `{"id":"t-none","name":"无授权","short":"无","root_domains":["n.cn"]}`)
	own.SetFingerprints(context.Background(), "t-none", ownership.Fingerprints{CertFPs: []string{"AA:BB:CC"}})
	resp, nb := post(t, srv.URL, "/v1/tenants/t-none/darkweb:inspect", "tok-admin", `{"samples":[`+ownedSampleJSON("S1")+`]}`)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(nb, "no_valid_scope") {
		t.Errorf("无授权巡检期望 403 no_valid_scope，实际 %d %s", resp.StatusCode, nb)
	}

	// ⑤ 无指纹基线（新租户有 scope 但无基线）→ 200 但 owned=0 且不出包
	post(t, srv.URL, "/v1/tenants", "tok-admin", `{"id":"t-nofp","name":"无基线","short":"无基线","root_domains":["f.cn"]}`)
	if err := az.Upsert(context.Background(), rbac.Principal{UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"r", authz.Scope{Tenant: "t-nofp", Domains: []string{"f.cn"}, ValidFrom: time.Now().Add(-time.Hour), ValidTo: time.Now().Add(time.Hour), Signer: "s", DocHash: "h"}); err != nil {
		t.Fatal(err)
	}
	resp, nb2 := post(t, srv.URL, "/v1/tenants/t-nofp/darkweb:inspect", "tok-admin", `{"samples":[`+ownedSampleJSON("S1")+`]}`)
	var r2 darkweb.Result
	_ = json.Unmarshal([]byte(nb2), &r2)
	if resp.StatusCode != http.StatusOK || r2.Owned != 0 || r2.PackageID != "" {
		t.Errorf("无基线须全疑似不出包: %d %s", resp.StatusCode, nb2)
	}
	if r2.Queued != 1 {
		t.Errorf("无基线样本应进复核队列: %+v", r2)
	}
}

// 为什么（FR-CHN-007 对外导出面）：导出必须真实可达且三闸同在——跨租户 404 不泄露存在性、
// md 正文带 X-Content-Sha256（独立复核）、内容含包 ID/量级区间/链路（通报交付物第一现场）。
func TestLeadPackageExportEndpoint(t *testing.T) {
	srv, own, az := newDarkServer(t)
	_, _ = post(t, srv.URL, "/v1/tenants", "tok-admin", `{"id":"t-a","name":"甲"}`)
	own.SetFingerprints(context.Background(), "t-a", ownership.Fingerprints{CertFPs: []string{"AA:BB:CC"}})
	_ = az.Upsert(context.Background(), rbac.Principal{Role: "R7", TenantIDs: []string{"*"}}, "r", authz.Scope{
		Tenant: "t-a", CIDRs: []string{"0.0.0.0/0"}, Signer: "t", DocHash: "h",
		ValidFrom: time.Now().Add(-time.Hour), ValidTo: time.Now().Add(time.Hour),
	})
	// 巡检产出包（归属样本 S1）
	resp, body := post(t, srv.URL, "/v1/tenants/t-a/darkweb:inspect", "tok-admin",
		`{"samples":[`+ownedSampleJSON("S1")+`]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("巡检应 200: %d %s", resp.StatusCode, body)
	}
	var res struct {
		PackageID string `json:"package_id"`
	}
	_ = json.Unmarshal([]byte(body), &res)
	if res.PackageID == "" {
		t.Fatal("应产出线索包")
	}
	// md 导出：要素齐 + 哈希头
	resp2, body2 := get2(srv.URL+"/v1/tenants/t-a/darkweb/packages/"+res.PackageID+"/export?format=md", "tok-admin")
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("导出应 200: %d %s", resp2.StatusCode, body2)
	}
	if resp2.Header.Get("X-Content-Sha256") == "" {
		t.Error("md 导出必须带 X-Content-Sha256（独立复核）")
	}
	for _, want := range []string{res.PackageID, "泄露规模", "交易链路", "样本 S1", "取证"} {
		if !strings.Contains(body2, want) {
			t.Errorf("导出文本缺要素 %q", want)
		}
	}
	// 跨租户=404（不泄露包存在性，AX-5）
	resp3, _ := get2(srv.URL+"/v1/tenants/t-b/darkweb/packages/"+res.PackageID+"/export?format=md", "tok-admin")
	if resp3.StatusCode != http.StatusNotFound {
		t.Errorf("跨租户导出期望 404，实际 %d", resp3.StatusCode)
	}
	// 默认=JSON 全量
	resp4, body4 := get2(srv.URL+"/v1/tenants/t-a/darkweb/packages/"+res.PackageID+"/export", "tok-admin")
	if resp4.StatusCode != http.StatusOK || !strings.Contains(body4, "package_id") {
		t.Error("默认导出应为 JSON 全量")
	}
}
