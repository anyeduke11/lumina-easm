package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/secret"
	"github.com/wangdev88/easm-platform/platform/services/internal/shadowit"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

const m3cKey = "AKIAIOSFODNN7EXAMPLE" // 形状样本（AKIA 前缀 + 20 位，非真实凭据）

func newM3CServer(t *testing.T, withSecret, withShadow bool) *httptest.Server {
	t.Helper()
	l := &audit.MemLog{}
	ts := tenant.NewMemStore()
	_ = ts.Create(nil, tenant.Tenant{ID: "t-c", Name: "M3C 取证单位", Short: "M3C", Status: "active",
		RootDomains: []string{"c.example.cn"}, CIDRs: []string{"198.51.103.0/24"}})
	tokens := map[string]rbac.Principal{"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}}}
	gms := graph.NewMemStore()
	gs := graph.NewService(gms)
	// 预置来源实体：密钥来自该域名资产（边才有锚点）
	if _, _, err := gs.UpsertEntity(context.Background(), graph.Entity{
		Kind: graph.KindDomain, Tenant: "t-c", Fingerprint: "dom:portal.c.example.cn",
		Props: map[string]string{"value": "portal.c.example.cn"}, InScope: true,
	}); err != nil {
		t.Fatal(err)
	}
	opts := []Option{}
	if withSecret {
		opts = append(opts, WithSecret(secret.New().WithGraph(gs)))
	}
	if withShadow {
		opts = append(opts, WithShadow(shadowit.New(ownership.NewService())))
	}
	srv := httptest.NewServer(New(tenant.NewService(ts, l),
		asset.NewService(asset.NewMemStore(), l), tokens, opts...).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func post2(t *testing.T, url, body string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer tok-admin")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func get3(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer tok-admin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func errCode(body string) string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal([]byte(body), &e)
	return e.Error.Code
}

// 为什么（FR-CHN-002 诚实边界）：未装外呼 provider 时，形状正确的密钥仍是
// 「不可验证」——端点必须如实标注 probe_enabled=false，不得返回 valid。
func TestSecretVerifyEndpoint(t *testing.T) {
	srv := newM3CServer(t, true, false)
	resp, body := post2(t, srv.URL+"/v1/tenants/t-c/secret:verify",
		`{"entries":[{"rule":"R-KEY","location":"app/config.js#L12","snippet":"`+m3cKey+`",
		"source_fp":"dom:portal.c.example.cn","evidence_ref":"evi:m3c-1"}]}`)
	if resp.StatusCode != 200 {
		t.Fatalf("verify 应 200: %d %s", resp.StatusCode, body)
	}
	var out struct {
		Total        int  `json:"total"`
		Linked       int  `json:"linked"`
		ProbeEnabled bool `json:"probe_enabled"`
		Verdicts     []struct {
			Status  string `json:"status"`
			Format  string `json:"format"`
			Graphed bool   `json:"graphed"`
			Linked  bool   `json:"linked"`
		} `json:"verdicts"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("响应解析失败: %v %s", err, body)
	}
	if out.Total != 1 || len(out.Verdicts) != 1 {
		t.Fatalf("应 1 条判定: %s", body)
	}
	v := out.Verdicts[0]
	if v.Format != "ok" || v.Status != "unverifiable" {
		t.Errorf("未外呼时应 ok/unverifiable: %s/%s", v.Format, v.Status)
	}
	if !v.Graphed {
		t.Error("判定应入图（度量分母）")
	}
	if v.Linked || out.Linked != 0 {
		t.Error("未验证为可用不得连边")
	}
	if out.ProbeEnabled {
		t.Error("未装配外呼 provider 时不得标注 probe_enabled")
	}
	// 缺 entries → 400
	r2, b2 := post2(t, srv.URL+"/v1/tenants/t-c/secret:verify", `{"entries":[]}`)
	if r2.StatusCode != 400 {
		t.Errorf("空 entries 应 400: %d %s", r2.StatusCode, b2)
	}
	// 跨租户（租户不存在）→ 非 200
	r3, _ := post2(t, srv.URL+"/v1/tenants/t-other/secret:verify",
		`{"entries":[{"rule":"R-KEY","location":"a.js#L1"}]}`)
	if r3.StatusCode == 200 {
		t.Error("跨租户/不存在租户不应 200")
	}
}

// 为什么（FR-CHN-002 误报率可度量）：度量端点必须给出分母与口径，
// 且判定落图后跨请求可累计（度量不是一次性快照）。
func TestSecretMetricsEndpoint(t *testing.T) {
	srv := newM3CServer(t, true, false)
	// 三条不同脱敏值的密钥（同脱敏值=同一凭据实体，不重复计入分母）
	for _, c := range [][2]string{
		{"a.js#L1", m3cKey},
		{"b.js#L2", "AKIA1234"}, // 长度不足 → invalid
		{"c.js#L3", "AKIA5678"}, // 长度不足 → invalid
	} {
		loc, snippet := c[0], c[1]
		r, b := post2(t, srv.URL+"/v1/tenants/t-c/secret:verify",
			`{"entries":[{"rule":"R-KEY","location":"`+loc+`","snippet":"`+snippet+`"}]}`)
		if r.StatusCode != 200 {
			t.Fatalf("verify 应 200: %d %s", r.StatusCode, b)
		}
	}
	resp, body := get3(t, srv.URL+"/v1/tenants/t-c/secret/metrics")
	if resp.StatusCode != 200 {
		t.Fatalf("metrics 应 200: %d %s", resp.StatusCode, body)
	}
	var m struct {
		Tenant   string         `json:"tenant"`
		Total    int            `json:"total"`
		ByStatus map[string]int `json:"by_status"`
		FPRate   float64        `json:"fp_rate"`
		Basis    string         `json:"basis"`
	}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	if m.Total != 3 {
		t.Errorf("度量分母应为 3: %d", m.Total)
	}
	if m.ByStatus["invalid"] != 2 || m.ByStatus["unverifiable"] != 1 {
		t.Errorf("状态分布不符: %+v", m.ByStatus)
	}
	if m.FPRate < 0.66 || m.FPRate > 0.67 {
		t.Errorf("误报率应 ≈2/3: %f", m.FPRate)
	}
	if m.Basis == "" || m.Tenant != "t-c" {
		t.Errorf("度量须带口径与租户: %s", body)
	}
}

// 为什么（红线落代码）：影子 IT 纳管必须「判定归属 + 人审人 + 动作=admit」三条全过；
// 疑似资产纳管必须 409 拒，缺人审人必须 400 拒——不靠文档约束。
func TestShadowAdviseAndAdmitEndpoints(t *testing.T) {
	srv := newM3CServer(t, false, true)
	// ① 归属资产建议：含纳管、且必须人审
	resp, body := post2(t, srv.URL+"/v1/tenants/t-c/shadow:advise",
		`{"domain":"portal.c.example.cn","signals":{"icp_subject":"M3C 取证单位"}}`)
	if resp.StatusCode != 200 {
		t.Fatalf("advise 应 200: %d %s", resp.StatusCode, body)
	}
	var out struct {
		Advice struct {
			ID          string `json:"id"`
			Verdict     string `json:"verdict"`
			NeedsReview bool   `json:"needs_review"`
			Actions     []struct {
				Code string `json:"code"`
			} `json:"actions"`
		} `json:"advice"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Advice.Verdict != ownership.VerdictOwned {
		t.Fatalf("主域资产应判归属: %s", body)
	}
	if !out.Advice.NeedsReview {
		t.Error("纳管必须人审")
	}
	hasAdmit := false
	for _, a := range out.Advice.Actions {
		if a.Code == "admit" {
			hasAdmit = true
		}
	}
	if !hasAdmit {
		t.Error("归属资产应给出纳管建议")
	}
	// ② 人审纳管 → 201（写入资产）
	admitBody := `{"domain":"portal.c.example.cn","signals":{"icp_subject":"M3C 取证单位"},
		"action":"admit","reviewer":"张三",
		"asset":{"id":"m3c-a1","type":"domain","name":"portal.c.example.cn","risk":"medium","exp":40,
		"owner":"IT","status":"在用","beian":"已备案","biz":"门户","found":"2026-10-19T00:00:00Z"}}`
	r2, b2 := post2(t, srv.URL+"/v1/tenants/t-c/shadow/admit", admitBody)
	if r2.StatusCode != 201 {
		t.Fatalf("归属+人审纳管应 201: %d %s", r2.StatusCode, b2)
	}
	if !bytes.Contains([]byte(b2), []byte(`"admitted":true`)) {
		t.Errorf("纳管响应须标注已纳管: %s", b2)
	}
	if !bytes.Contains([]byte(b2), []byte("M3-C 纳管/复核人:张三")) {
		t.Errorf("入账资产须留下人审来源（谁纳的）: %s", b2)
	}
	// ③ 疑似资产纳管 → 409（红线）
	r3, b3 := post2(t, srv.URL+"/v1/tenants/t-c/shadow/admit",
		`{"domain":"portal.other-net.io","signals":{"keyword_cooccur":2},"action":"admit","reviewer":"张三",
		"asset":{"id":"m3c-a2","type":"domain","name":"portal.other-net.io","risk":"medium","exp":40,
		"owner":"IT","status":"在用","beian":"未备案","biz":"外域"}}`)
	if r3.StatusCode != 409 || errCode(b3) != "not_owned" {
		t.Errorf("疑似资产纳管应 409 not_owned: %d %s", r3.StatusCode, b3)
	}
	// ④ 缺人审人 → 400
	r4, b4 := post2(t, srv.URL+"/v1/tenants/t-c/shadow/admit",
		`{"domain":"portal.c.example.cn","action":"admit","asset":{"id":"m3c-a3","type":"domain","name":"portal.c.example.cn"}}`)
	if r4.StatusCode != 400 || errCode(b4) != "review_required" {
		t.Errorf("缺 reviewer 应 400 review_required: %d %s", r4.StatusCode, b4)
	}
	// ⑤ 建议面无副作用：纳管前资产列表不含该资产（advise 不写资产）
	r5, b5 := get3(t, srv.URL+"/v1/tenants/t-c/assets")
	if r5.StatusCode != 200 {
		t.Fatalf("assets 应 200: %d", r5.StatusCode)
	}
	var list struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal([]byte(b5), &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 1 {
		t.Errorf("仅人审纳管的 1 条资产应入账（advise 不写资产）: %d", list.Total)
	}
}

// 为什么（诚实边界）：M3-C 组件未装配时端点一律 501，不返回空判定/空建议冒充已验证。
func TestM3CUnavailableIs501(t *testing.T) {
	srv := newM3CServer(t, false, false)
	for _, p := range []string{
		"/v1/tenants/t-c/secret:verify",
		"/v1/tenants/t-c/secret/metrics",
		"/v1/tenants/t-c/shadow:advise",
		"/v1/tenants/t-c/shadow/admit",
	} {
		var (
			resp *http.Response
			body string
		)
		if p == "/v1/tenants/t-c/secret/metrics" {
			resp, body = get3(t, srv.URL+p)
		} else {
			resp, body = post2(t, srv.URL+p, `{"entries":[{"rule":"R-KEY","location":"a.js#L1"}]}`)
		}
		if resp.StatusCode != 501 {
			t.Errorf("%s 未装配应 501: %d %s", p, resp.StatusCode, body)
		}
		if errCode(body) == "" {
			t.Errorf("%s 501 须带 machine-readable code: %s", p, body)
		}
	}
}
