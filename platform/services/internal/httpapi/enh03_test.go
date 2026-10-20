package httpapi

// ENH-03 接缝端点测试：M3-D 多模态判敏（mm:analyze）、灰度放量动作面（evalset/promote）、
// M3-C-AI 文案（shadow:advise with_ai）。501=能力边界（未装配）；红线由域层测试锁定。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/ai"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/evalset"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/mm"
	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/shadowit"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

// fakeAI 端点级 mock（不依赖真实上游）。
type fakeAI struct{ content string }

func (f fakeAI) Name() string { return "fake" }
func (f fakeAI) Chat(_ context.Context, _ ai.ChatRequest) (ai.ChatResponse, error) {
	return ai.ChatResponse{Content: f.content, Model: "fake-1"}, nil
}

func newEnhServer(t *testing.T, withMM bool, withShadowAI bool) *httptest.Server {
	t.Helper()
	l := &audit.MemLog{}
	ctx := context.Background()
	ts := tenant.NewMemStore()
	_ = ts.Create(ctx, tenant.Tenant{ID: "t-a", Name: "甲", Status: "active",
		RootDomains: []string{"hddata.cn"}})
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
	}
	var p ai.Provider
	if withMM || withShadowAI {
		p = fakeAI{content: `{"sensitive":false,"kind":"benign","findings":[],"basis":"无敏感内容"}`}
	}
	opts := []Option{WithShadow(shadowit.New(ownership.NewService()))}
	if withShadowAI && p != nil {
		opts[0] = WithShadow(shadowit.New(ownership.NewService()).WithAI(p))
	}
	h := New(tenant.NewService(ts, l), nil, tokens, opts...)
	if withMM {
		h = New(tenant.NewService(ts, l), nil, tokens,
			WithShadow(shadowit.New(ownership.NewService()).WithAI(p)),
			WithMM(mm.New(p, graph.NewService(graph.NewMemStore()))))
	}
	srv := httptest.NewServer(h.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func TestMmUnavailable501(t *testing.T) {
	srv := newEnhServer(t, false, false)
	resp, body := post(t, srv.URL, "/v1/tenants/t-a/mm:analyze", "tok-admin",
		`{"image_url":"data:image/png;base64,AA"}`)
	if resp.StatusCode != http.StatusNotImplemented || !strings.Contains(body, "mm_unavailable") {
		t.Fatalf("ENH-03 未装配应 501 mm_unavailable: %d %s", resp.StatusCode, body)
	}
}

func TestMmAnalyzeEndpoint(t *testing.T) {
	srv := newEnhServer(t, true, false)
	resp, body := post(t, srv.URL, "/v1/tenants/t-a/mm:analyze", "tok-admin",
		`{"image_url":"data:image/png;base64,AA"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("期望 200，实际 %d %s", resp.StatusCode, body)
	}
	var out struct {
		Result struct {
			Kind       string `json:"kind"`
			AIAssisted bool   `json:"ai_assisted"`
			Graphed    bool   `json:"graphed"`
			Model      string `json:"model"`
		} `json:"result"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	if out.Result.Kind != "benign" || !out.Result.AIAssisted || out.Result.Graphed || out.Result.Model != "fake-1" {
		t.Fatalf("判定元数据不符: %s", body)
	}
	// 缺图片=400
	resp2, _ := post(t, srv.URL, "/v1/tenants/t-a/mm:analyze", "tok-admin", `{}`)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("缺 image_url 期望 400，实际 %d", resp2.StatusCode)
	}
}

func TestEvalPromoteBlocked403(t *testing.T) {
	srv := newEvalServer(t)
	resp, body := post(t, srv.URL, "/v1/tenants/t-a/evalset/promote", "tok-admin", `{"by":"u1"}`)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "eval_gate_blocked") {
		t.Fatalf("门禁未放行放量应 403 eval_gate_blocked: %d %s", resp.StatusCode, body)
	}
}

func TestEvalPromoteOK200(t *testing.T) {
	srv := newEvalServer(t, func(ev *evalset.Service) {
		ev.WithThresholds(evalset.Thresholds{F1Min: 0, FPRateMax: 1, KappaMin: 0, HallucinationMax: 1, MinSamples: 1})
	})
	// 导入 1 样本 + 跑评测（1 样本即可过 MinSamples=1 的放宽口径）
	_, _ = post(t, srv.URL, "/v1/tenants/t-a/evalset/samples", "tok-admin",
		`{"by":"u1","samples":[{"kind":"sens","text":"s1","expected":true}]}`)
	_, _ = post(t, srv.URL, "/v1/tenants/t-a/evalset:run", "tok-admin", `{}`)
	resp, body := post(t, srv.URL, "/v1/tenants/t-a/evalset/promote", "tok-admin",
		`{"by":"u1","note":"灰度放量示证"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("门禁放行后放量应 200: %d %s", resp.StatusCode, body)
	}
	var out struct {
		Promote struct {
			ID        string `json:"id"`
			RunID     string `json:"run_id"`
			GateAllow bool   `json:"gate_allow"`
		} `json:"promote"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	if !strings.HasPrefix(out.Promote.ID, "EP-") || out.Promote.RunID == "" || !out.Promote.GateAllow {
		t.Fatalf("放量留痕不符: %s", body)
	}
}

func TestShadowAdviseWithAI(t *testing.T) {
	// 未装配 provider：with_ai=true → 501 ai_unavailable（诚实边界）
	srv := newEnhServer(t, false, false)
	resp, body := post(t, srv.URL, "/v1/tenants/t-a/shadow:advise", "tok-admin",
		`{"domain":"portal.hddata.cn","with_ai":true}`)
	if resp.StatusCode != http.StatusNotImplemented || !strings.Contains(body, "ai_unavailable") {
		t.Fatalf("with_ai 但未装配应 501 ai_unavailable: %d %s", resp.StatusCode, body)
	}
	// 已装配：200 + ai_basis 文案层注入（动作集红线由域层测试锁定）
	srv2 := newEnhServer(t, false, true)
	resp2, body2 := post(t, srv2.URL, "/v1/tenants/t-a/shadow:advise", "tok-admin",
		`{"domain":"portal.hddata.cn","with_ai":true}`)
	if resp2.StatusCode != http.StatusOK || !strings.Contains(body2, "ai_basis") {
		t.Fatalf("with_ai 装配后应 200 且含 ai_basis: %d %s", resp2.StatusCode, body2)
	}
	// 默认（不带 with_ai）：确定性路径，advice 无 AI 字段
	resp3, body3 := post(t, srv2.URL, "/v1/tenants/t-a/shadow:advise", "tok-admin",
		`{"domain":"portal.hddata.cn"}`)
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("默认路径应 200: %d %s", resp3.StatusCode, body3)
	}
	var def struct {
		Advice struct {
			AIBasis string `json:"ai_basis"`
		} `json:"advice"`
	}
	_ = json.Unmarshal([]byte(body3), &def)
	if def.Advice.AIBasis != "" {
		t.Fatalf("默认路径不得引入 AI 字段: %s", body3)
	}
}
