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
	"github.com/wangdev88/easm-platform/platform/services/internal/classify"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/sweep"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

func newSweepServer(t *testing.T) *httptest.Server {
	t.Helper()
	l := &audit.MemLog{}
	ctx := context.Background()
	ts := tenant.NewMemStore()
	_ = ts.Create(ctx, tenant.Tenant{ID: "t-a", Name: "甲", Status: "active"})
	astore := asset.NewMemStore()
	_ = astore.Create(ctx, asset.Asset{ID: "sa-1", Tenant: "t-a", Name: "backup.hddata.cn", Type: "web", TypeLabel: "网站",
		Risk: "high", Exp: 70, Owner: "运维部", Found: time.Now().UTC(), Status: "在用",
		Beian: "已备案", Source: "P3/Dirsearch", Biz: "备份", IP: "192.168.1.7", Ports: []int{6379}})
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"tok-tb":    {UserID: "u9", Role: "R1", TenantIDs: []string{"t-b"}},
	}
	led := ledger.NewService(ledger.NewMemStore(), l)
	srv := httptest.NewServer(New(
		tenant.NewService(ts, l), asset.NewService(astore, l), tokens,
		WithLedger(led), WithSweep(sweep.NewService(astore, classify.New(), led)),
	).Handler())
	t.Cleanup(srv.Close)
	return srv
}

// 为什么（FR-DSC-002/003 / 一票否决①）：端点执行的阶段/步骤口径与产出联动台账。
func TestSweepEndpoints(t *testing.T) {
	srv := newSweepServer(t)
	resp, body := post(t, srv.URL, "/v1/sweeps", "tok-admin", `{"tenant_id":"t-a","phases":["P3"]}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("创建期望 201，实际 %d %s", resp.StatusCode, body)
	}
	var sw map[string]any
	_ = json.Unmarshal([]byte(body), &sw)
	if sw["status"] != "done" {
		t.Errorf("MVP 同步完成应为 done: %s", body)
	}
	if int(sw["findings"].(float64)) == 0 {
		t.Errorf("内网+端口资产应有发现: %s", body)
	}
	// 联动台账
	_, ledBody := get2(srv.URL+"/v1/ledger", "tok-admin")
	if !strings.Contains(ledBody, "R-PORT") && !strings.Contains(ledBody, "R-INTRANET") {
		t.Errorf("台账应含 sweep 入账条目: %s", ledBody)
	}
	// 矩阵
	_, mx := get2(srv.URL+"/v1/sweeps/matrix", "tok-admin")
	var matrix struct {
		Rows []struct {
			Tenant string    `json:"tenant"`
			Cov    []float64 `json:"cov"`
		} `json:"rows"`
	}
	_ = json.Unmarshal([]byte(mx), &matrix)
	if len(matrix.Rows) != 1 || len(matrix.Rows[0].Cov) != 5 {
		t.Fatalf("矩阵形状错误: %s", mx)
	}
	if matrix.Rows[0].Cov[2] != 1.0 {
		t.Errorf("P3 覆盖度应为 1，实际 %v", matrix.Rows[0].Cov[2])
	}
	// List/Get
	_, ls := get2(srv.URL+"/v1/sweeps", "tok-admin")
	if !strings.Contains(ls, "\"total\":1") {
		t.Errorf("列表应 1 条: %s", ls)
	}
	id := sw["id"].(string)
	_, gs := get2(srv.URL+"/v1/sweeps/"+id, "tok-admin")
	if !strings.Contains(gs, id) {
		t.Errorf("Get 应返回任务: %s", gs)
	}
}

// 跨租户触发必须拒绝（FR-DSC-013 边界）。
func TestSweepCrossTenantDenied(t *testing.T) {
	srv := newSweepServer(t)
	resp, _ := post(t, srv.URL, "/v1/sweeps", "tok-tb", `{"tenant_id":"t-a","phases":["P1"]}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("期望 403，实际 %d", resp.StatusCode)
	}
}

// 未知阶段拒绝（阶段口径唯一 C-2）。
func TestSweepUnknownPhase(t *testing.T) {
	srv := newSweepServer(t)
	resp, _ := post(t, srv.URL, "/v1/sweeps", "tok-admin", `{"tenant_id":"t-a","phases":["P9"]}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("未知阶段期望 400，实际 %d", resp.StatusCode)
	}
}
