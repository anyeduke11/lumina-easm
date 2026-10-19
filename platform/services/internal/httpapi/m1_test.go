package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/authz"
	"github.com/wangdev88/easm-platform/platform/services/internal/classify"
	"github.com/wangdev88/easm-platform/platform/services/internal/intel"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
	"github.com/wangdev88/easm-platform/platform/services/internal/notify"
	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
	"github.com/wangdev88/easm-platform/platform/services/internal/plugin"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/sweep"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
	"github.com/wangdev88/easm-platform/platform/services/internal/vuln"
)

func newM1Server(t *testing.T) *httptest.Server {
	t.Helper()
	l := &audit.MemLog{}
	tsvc := tenant.NewService(tenant.NewMemStore(), l)
	astore := asset.NewMemStore()
	led := ledger.NewService(ledger.NewMemStore(), l)
	az := authz.NewService(authz.NewMemStore(), l)
	sw := sweep.NewService(astore, classify.New(), led)
	sw.SetScope(az)
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"tok-tb":    {UserID: "u9", Role: "R1", TenantIDs: []string{"t-b"}},
	}
	v, i, o := vuln.NewService(), intel.NewService(), ownership.NewService()
	m := monitor.New(v, i, func() map[string][]asset.Asset { return nil }) // 测试面：调度 provider 空，事件/手动走请求可见面
	srv := httptest.NewServer(New(tsvc, asset.NewService(astore, l), tokens,
		WithLedger(led), WithSweep(sw), WithAuthz(az), WithPlugins(plugin.NewRegistry()),
		WithKnowledge(v, i, o), WithMonitor(m), WithNotify(notify.New())).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func TestM1SyntaxEndpoints(t *testing.T) {
	srv := newM1Server(t)
	_, body := get2(srv.URL+"/v1/syntax", "tok-admin")
	var out struct {
		Groups []struct {
			G     string `json:"g"`
			Ph    string `json:"ph"`
			Items []any  `json:"items"`
		} `json:"groups"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	if len(out.Groups) != 12 {
		t.Fatalf("目录应 12 组，实际 %d", len(out.Groups))
	}
	// render：合法 4 参数 → ≥16 无残留；缺参 → 400
	resp, body := post(t, srv.URL, "/v1/syntax:render", "tok-admin", `{"org":"甲","short":"甲","domain":"a.cn","cidr":"1.2.3.0/24"}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "site:a.cn") {
		t.Errorf("render 期望 200+site:a.cn，实际 %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "\\{") && strings.Contains(body, "{domain}") {
		t.Error("渲染输出不应残留占位符")
	}
	resp2, _ := post(t, srv.URL, "/v1/syntax:render", "tok-admin", `{"org":"甲"}`)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("缺参期望 400，实际 %d", resp2.StatusCode)
	}
}

// 为什么（一票否决⑥端到端）：未授权租户执行排查 403；录入 scope 后放行；越界目标 check 拒绝。
func TestM1AuthzGatesSweep(t *testing.T) {
	srv := newM1Server(t)
	// 建租户
	post(t, srv.URL, "/v1/tenants", "tok-admin", `{"id":"t-g","name":"网关公司"}`)
	// 无 scope → sweeps 403（no_valid_scope）
	resp, body := post(t, srv.URL, "/v1/sweeps", "tok-admin", `{"tenant_id":"t-g","phases":["P1"]}`)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "no_valid_scope") {
		t.Fatalf("未授权执行期望 403 no_valid_scope，实际 %d %s", resp.StatusCode, body)
	}
	// 录入 scope
	resp2, _ := post(t, srv.URL, "/v1/tenants/t-g/authz", "tok-admin",
		`{"domains":["g.cn"],"cidrs":["10.1.0.0/16"],"valid_to":"2027-01-01T00:00:00Z","signer":"s","doc_hash":"h"}`)
	if resp2.StatusCode != http.StatusCreated {
		t.Fatalf("scope 录入期望 201，实际 %d", resp2.StatusCode)
	}
	resp3, _ := post(t, srv.URL, "/v1/sweeps", "tok-admin", `{"tenant_id":"t-g","phases":["P1"]}`)
	if resp3.StatusCode != http.StatusCreated {
		t.Fatalf("授权后执行期望 201，实际 %d", resp3.StatusCode)
	}
	// authz:check 越界拒绝 + 界内通过
	_, ck := post(t, srv.URL, "/v1/authz:check", "tok-admin", `{"tenant_id":"t-g","target":"evil.com","port":443}`)
	if strings.Contains(ck, "\"allowed\":true") {
		t.Error("越界目标不应放行")
	}
	_, ok := post(t, srv.URL, "/v1/authz:check", "tok-admin", `{"tenant_id":"t-g","target":"api.g.cn","port":443}`)
	if !strings.Contains(ok, "\"allowed\":true") {
		t.Errorf("子域应放行，实际 %s", ok)
	}
}

// 插件注册：合法契约 201、非法契约 422 带字段、主动类缺 authz 422、卸载 200。
func TestM1PluginEndpoints(t *testing.T) {
	srv := newM1Server(t)
	good := `{"id":"dsh-tool-asm-subfinder","cmd":"subfinder -json","src":"github.com/pd/subfinder","cap":"discover","risk":"只读","auth":false,"lic":"MIT","out":"subdomains[]","sub_code":"MAP-2","image":"easm/tool-subfinder:1.6.2","res_class":"M","net_class":"passive","lic_mode":"main-image"}`
	resp, body := post(t, srv.URL, "/v1/plugins", "tok-admin", good)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("合法契约期望 201，实际 %d %s", resp.StatusCode, body)
	}
	bad := `{"id":"junk"}`
	resp2, body2 := post(t, srv.URL, "/v1/plugins", "tok-admin", bad)
	if resp2.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body2, "id") {
		t.Errorf("非法契约期望 422 指字段，实际 %d %s", resp2.StatusCode, body2)
	}
	activeNoAuth := `{"id":"dsh-tool-scan-naabu","cmd":"naabu","src":"s","cap":"port","risk":"受控","auth":false,"lic":"MIT","out":"ports[]","sub_code":"SCAN-1","image":"easm/tool-naabu:2.3.1","res_class":"L","net_class":"active-high"}`
	resp3, _ := post(t, srv.URL, "/v1/plugins", "tok-admin", activeNoAuth)
	if resp3.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("active-high 缺 authz 应 422（C-4），实际 %d", resp3.StatusCode)
	}
	_, ls := get2(srv.URL+"/v1/plugins", "tok-admin")
	if !strings.Contains(ls, "subfinder") {
		t.Errorf("列表应含已注册插件: %s", ls)
	}
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/v1/plugins/dsh-tool-asm-subfinder", nil)
	req.Header.Set("Authorization", "Bearer tok-admin")
	resp4, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Errorf("卸载期望 200，实际 %d", resp4.StatusCode)
	}
}
