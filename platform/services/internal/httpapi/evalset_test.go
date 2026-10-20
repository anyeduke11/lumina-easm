package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/evalset"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

// newEvalServer 双租户 + R7/R1/R5 三令牌 + 台账与评测集共用内存实现
// （与 newTestServer 同形态；评测集服务在测试内装配=可断言装配语义）。
func newEvalServer(t *testing.T, evalOpts ...func(*evalset.Service)) *httptest.Server {
	t.Helper()
	l := &audit.MemLog{}
	ctx := context.Background()
	ts := tenant.NewMemStore()
	for _, id := range []string{"t-a", "t-b"} {
		_ = ts.Create(ctx, tenant.Tenant{ID: id, Name: id, Status: "active"})
	}
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"tok-ta":    {UserID: "u1", Role: "R1", TenantIDs: []string{"t-a"}},
		"tok-ro":    {UserID: "u5", Role: "R5", TenantIDs: []string{"t-a"}},
	}
	led := ledger.NewService(ledger.NewMemStore(), l)
	ev := evalset.New(evalset.NewMemStore())
	for _, f := range evalOpts {
		f(ev)
	}
	srv := httptest.NewServer(New(tenant.NewService(ts, l), nil, tokens,
		WithLedger(led), WithEval(ev)).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func TestEvalGateFailClosedEndpoint(t *testing.T) {
	srv := newEvalServer(t)
	resp, body := get2(srv.URL+"/v1/tenants/t-a/evalset/gate", "tok-admin")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("期望 200，实际 %d %s", resp.StatusCode, body)
	}
	var out struct {
		Gate struct {
			Allow   bool     `json:"allow"`
			Reasons []string `json:"reasons"`
		} `json:"gate"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	if out.Gate.Allow || len(out.Gate.Reasons) == 0 {
		t.Fatalf("无评测记录必须 fail closed 且说明原因: %s", body)
	}
}

func TestEvalAddRunGateFlow(t *testing.T) {
	srv := newEvalServer(t)
	// 导入样本（缺 by=400：人在环可追溯）
	resp, _ := post(t, srv.URL, "/v1/tenants/t-a/evalset/samples", "tok-admin",
		`{"samples":[{"kind":"sens","text":"-----BEGIN RSA PRIVATE KEY-----"}]}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("缺标注人期望 400，实际 %d", resp.StatusCode)
	}
	resp, body := post(t, srv.URL, "/v1/tenants/t-a/evalset/samples", "tok-admin",
		`{"by":"u1","samples":[
			{"kind":"sens","text":"-----BEGIN RSA PRIVATE KEY-----\nMIIBOg==","expected":true},
			{"kind":"sens","text":"今日天气晴朗","expected":false}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("导入样本期望 200，实际 %d %s", resp.StatusCode, body)
	}
	// 运行评测（确定性判敏对象；默认阈值下 deny=样本不足）
	resp, body = post(t, srv.URL, "/v1/tenants/t-a/evalset:run", "tok-admin", `{}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("评测运行期望 200，实际 %d %s", resp.StatusCode, body)
	}
	var out struct {
		Run struct {
			Subject string `json:"subject"`
			Total   int    `json:"total"`
			Gate    struct {
				Allow   bool     `json:"allow"`
				Reasons []string `json:"reasons"`
			} `json:"gate"`
		} `json:"run"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	if out.Run.Subject != "classify-22rules" || out.Run.Total != 2 {
		t.Fatalf("运行元数据不符: %s", body)
	}
	if out.Run.Gate.Allow {
		t.Fatalf("默认阈值（样本≥30）下必须不放量: %s", body)
	}
	// 运行历史
	resp, body = get2(srv.URL+"/v1/tenants/t-a/evalset/runs", "tok-admin")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("运行历史期望 200，实际 %d", resp.StatusCode)
	}
	var runs struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal([]byte(body), &runs)
	if runs.Total != 1 {
		t.Fatalf("运行历史期望 1 条: %s", body)
	}
}

func TestEvalRefluxEndpoint(t *testing.T) {
	srv := newEvalServer(t)
	// 台账条目：反证成立（示例占位符）→ 回流为误报样本
	_, _ = post(t, srv.URL, "/v1/tenants/t-a/ledger", "tok-admin",
		`{"id":"L-2026-0001","phase":"P3","cat":"代码密码类","asset":"a.cn","title":"示例路径命中 AKIA 私钥",
		  "lv":"中","src":"P3/Dirsearch","date":"2026-10-17T00:00:00Z","action":"删除","owner":"运维部","due":"2026-10-18T00:00:00Z",
		  "refute":[{"claim":"命中值为示例占位符","outcome":"confirmed","evidence":"testdata/demo.sql"}]}`)
	resp, body := post(t, srv.URL, "/v1/tenants/t-a/evalset/reflux", "tok-admin", `{"by":"u1"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("回流期望 200，实际 %d %s", resp.StatusCode, body)
	}
	var out struct {
		Added   int `json:"added"`
		Samples []struct {
			LedgerID string `json:"ledger_id"`
			Expected bool   `json:"expected"`
			Source   string `json:"source"`
		} `json:"samples"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	if out.Added != 1 || len(out.Samples) != 1 || out.Samples[0].LedgerID != "L-2026-0001" ||
		out.Samples[0].Expected || out.Samples[0].Source != "reflux" {
		t.Fatalf("反证成立应回流为误报样本: %s", body)
	}
	// 幂等：重放 added=0
	resp, body = post(t, srv.URL, "/v1/tenants/t-a/evalset/reflux", "tok-admin", `{"by":"u1"}`)
	_ = json.Unmarshal([]byte(body), &out)
	if resp.StatusCode != http.StatusOK || out.Added != 0 {
		t.Fatalf("重复回流应幂等: %d %s", resp.StatusCode, body)
	}
}

func TestEvalRelabelEndpoint(t *testing.T) {
	srv := newEvalServer(t)
	_, body := post(t, srv.URL, "/v1/tenants/t-a/evalset/samples", "tok-admin",
		`{"by":"u1","samples":[{"kind":"sens","text":"样本文本","expected":true}]}`)
	var added struct {
		Samples []struct {
			ID string `json:"id"`
		} `json:"samples"`
	}
	_ = json.Unmarshal([]byte(body), &added)
	sid := added.Samples[0].ID
	// expected 缺失=400
	resp, _ := post(t, srv.URL, "/v1/tenants/t-a/evalset/relabel", "tok-admin", `{"sample_id":"`+sid+`","by":"u2"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("缺 expected 期望 400，实际 %d", resp.StatusCode)
	}
	resp, body2 := post(t, srv.URL, "/v1/tenants/t-a/evalset/relabel", "tok-admin",
		`{"sample_id":"`+sid+`","expected":true,"by":"u2"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("二次标注期望 200，实际 %d %s", resp.StatusCode, body2)
	}
	// κ 接线：二次标注后运行，kappa_cover=1
	_, _ = post(t, srv.URL, "/v1/tenants/t-a/evalset:run", "tok-admin", `{}`)
	_, body3 := get2(srv.URL+"/v1/tenants/t-a/evalset/runs", "tok-admin")
	if !strings.Contains(body3, `"kappa_cover":1`) {
		t.Fatalf("运行应含 kappa_cover=1: %s", body3)
	}
}

func TestEvalPermissionAndScope(t *testing.T) {
	srv := newEvalServer(t)
	// R5 只读：写面 403
	resp, _ := post(t, srv.URL, "/v1/tenants/t-a/evalset/samples", "tok-ro",
		`{"by":"u5","samples":[{"kind":"sens","text":"x"}]}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("R5 写评测集期望 403，实际 %d", resp.StatusCode)
	}
	// R1 跨租户：非本租户 403（tenant.Get 作用域闸）
	resp2, _ := post(t, srv.URL, "/v1/tenants/t-b/evalset/samples", "tok-ta",
		`{"by":"u1","samples":[{"kind":"sens","text":"x"}]}`)
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("跨租户写评测集期望 403，实际 %d", resp2.StatusCode)
	}
}
