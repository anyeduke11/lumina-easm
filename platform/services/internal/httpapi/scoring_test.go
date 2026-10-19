package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/scoring"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

func newScoreServer(t *testing.T) *httptest.Server {
	t.Helper()
	l := &audit.MemLog{}
	ts := tenant.NewMemStore()
	if err := ts.Create(nil, tenant.Tenant{ID: "t-sc", Name: "评分租户", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
	}
	srv := httptest.NewServer(New(tenant.NewService(ts, l), asset.NewService(asset.NewMemStore(), l), tokens,
		WithLedger(ledger.NewService(ledger.NewMemStore(), l)),
		WithScoring(scoring.DefaultWeights(), scoring.DefaultThresholds())).Handler())
	t.Cleanup(srv.Close)
	return srv
}

// 为什么（FR-MIN-001/002）：评分端点必须直出可复算明细（贡献之和=总分）、
// 口径来源显式标注（默认待 G8-01 定稿），且跨租户不泄露资产存在性（AX-5）。
func TestAssetScoreEndpoint(t *testing.T) {
	srv := newScoreServer(t)
	r1, b1 := post(t, srv.URL, "/v1/tenants/t-sc/assets", "tok-admin",
		`{"id":"a-1","name":"资产1","type":"web","ip":"203.0.113.9","risk":"medium","owner":"sec","beian":"已备案","source":"P2/Fofa","found":"2026-10-18T00:00:00Z","status":"在用"}`)
	if r1.StatusCode != 200 && r1.StatusCode != 201 {
		t.Fatalf("建资产失败: %d %s", r1.StatusCode, b1)
	}
	r2, b2 := post(t, srv.URL, "/v1/tenants/t-sc/ledger", "tok-admin",
		`{"id":"L-sc-1","phase":"P1","cat":"代码密码类","asset":"a-1","title":"泄露条目","lv":"高","src":"搜索引擎","date":"2026-10-18T00:00:00Z","action":"删除","owner":"sec","due":"2026-10-25T00:00:00Z"}`)
	if r2.StatusCode != 200 && r2.StatusCode != 201 {
		t.Fatalf("建台账失败: %d %s", r2.StatusCode, b2)
	}

	resp, body := get2(srv.URL+"/v1/tenants/t-sc/assets/a-1/score", "tok-admin")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("评分期望 200: %d %s", resp.StatusCode, body)
	}
	var res struct {
		Score        float64 `json:"score"`
		Level        string  `json:"level"`
		WeightSource string  `json:"weight_source"`
		Factors      []struct {
			Code         string  `json:"code"`
			Raw          float64 `json:"raw"`
			Weight       int     `json:"weight"`
			Contribution float64 `json:"contribution"`
			Basis        string  `json:"basis"`
		} `json:"factors"`
		Inputs struct {
			ExposureHits      int  `json:"exposure_hits"`
			CredentialHits    int  `json:"credential_hits"`
			PubliclyReachable bool `json:"publicly_reachable"`
		} `json:"inputs"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Factors) != 4 {
		t.Fatalf("四因子明细应 4 项: %d", len(res.Factors))
	}
	sum := 0.0
	for _, f := range res.Factors {
		sum += f.Contribution
		if f.Basis == "" {
			t.Errorf("因子 %s 缺依据", f.Code)
		}
	}
	if diff := sum - res.Score; diff > 0.01 || diff < -0.01 {
		t.Errorf("明细贡献之和应=总分（可复算）: %v vs %v", sum, res.Score)
	}
	if !strings.Contains(res.WeightSource, "G8-01") {
		t.Errorf("口径来源须标注待定稿: %q", res.WeightSource)
	}
	if res.Inputs.ExposureHits != 1 || res.Inputs.CredentialHits != 1 || !res.Inputs.PubliclyReachable {
		t.Errorf("输入聚合不符（P1 命中/凭证/公网可达）: %+v", res.Inputs)
	}

	// 口径面
	resp2, body2 := get2(srv.URL+"/v1/tenants/t-sc/scoring/weights", "tok-admin")
	if resp2.StatusCode != http.StatusOK || !strings.Contains(body2, "G8-01") || !strings.Contains(body2, "exposure") {
		t.Errorf("口径端点异常: %d %s", resp2.StatusCode, body2)
	}

	// 跨租户=404（不泄露存在性）
	resp3, _ := get2(srv.URL+"/v1/tenants/t-other/assets/a-1/score", "tok-admin")
	if resp3.StatusCode == http.StatusOK {
		t.Error("跨租户评分不得 200")
	}
}
