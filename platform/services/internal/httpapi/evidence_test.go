package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

// 为什么（ENH-05 / C-5）：证据 REST 必须①固化后可按 ref 回溯同一字节，
// ②同内容同租户二次写=WORM 拒绝（409），③越权/租户错配一律 403（不靠 Provider 内部路径），
// ④未知 ref=404（不静默空返回）。用 FileStore（t.TempDir 隔离）测面，不依赖外部服务。
func newEvidServer(t *testing.T) *httptest.Server {
	t.Helper()
	l := &audit.MemLog{}
	tsvc := tenant.NewService(tenant.NewMemStore(), l)
	asvc := asset.NewService(asset.NewMemStore(), l)
	fs, err := evidence.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tokens := map[string]rbac.Principal{
		"tok-admin": {UserID: "u7", Role: "R7", TenantIDs: []string{"*"}},
		"tok-tb":    {UserID: "u9", Role: "R1", TenantIDs: []string{"t-b"}},
		"tok-ro":    {UserID: "u3", Role: "R3", TenantIDs: []string{"*"}}, // 只读：测写闸
	}
	srv := httptest.NewServer(New(tsvc, asvc, tokens, WithEvidence(fs)).Handler())
	t.Cleanup(srv.Close)
	return srv
}

type evidResp struct {
	Ref     string `json:"ref"`
	Sha256  string `json:"sha256"`
	Size    int    `json:"size"`
	Backend string `json:"backend"`
}

func TestEvidencePutGetRoundTrip(t *testing.T) {
	srv := newEvidServer(t)
	payload := "raw-jsonl-evidence-\x01line1\nline2"
	resp, body := post(t, srv.URL, "/v1/evidence?tenant=t-a", "tok-admin", payload)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT 应 201，实际 %d %s", resp.StatusCode, body)
	}
	var out evidResp
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("PUT 响应解析: %v (%s)", err, body)
	}
	if out.Sha256 != evidence.Hash([]byte(payload)) || out.Size != len(payload) {
		t.Errorf("哈希/大小不符: %s/%d", out.Sha256, out.Size)
	}
	if !strings.HasPrefix(out.Ref, "file://") || !strings.Contains(out.Ref, "/t-a/") {
		t.Errorf("ref 形态错误: %s", out.Ref)
	}
	// 回溯同一字节
	gresp, gbody := get2(srv.URL+"/v1/evidence?tenant=t-a&ref="+out.Ref, "tok-admin")
	if gresp.StatusCode != http.StatusOK || gbody != payload {
		t.Errorf("GET 回溯失败: %d len=%d want len=%d", gresp.StatusCode, len(gbody), len(payload))
	}
	if gresp.Header.Get("X-Evidence-Sha256") != out.Sha256 {
		t.Errorf("回溯哈希应一致，实际 %s", gresp.Header.Get("X-Evidence-Sha256"))
	}
}

func TestEvidenceWORMConflict(t *testing.T) {
	srv := newEvidServer(t)
	post(t, srv.URL, "/v1/evidence?tenant=t-a", "tok-admin", "same-evidence")
	resp, body := post(t, srv.URL, "/v1/evidence?tenant=t-a", "tok-admin", "same-evidence")
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "evidence_immutable") {
		t.Errorf("同内容重写应 409 evidence_immutable，实际 %d %s", resp.StatusCode, body)
	}
}

func TestEvidenceEmptyAndCrossTenant(t *testing.T) {
	srv := newEvidServer(t)
	// 空体 → 400
	if resp, _ := post(t, srv.URL, "/v1/evidence?tenant=t-a", "tok-admin", ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("空证据应 400，实际 %d", resp.StatusCode)
	}
	// 只读角色写 → 403（无 PermWriteAssets）
	if resp, _ := post(t, srv.URL, "/v1/evidence?tenant=t-a", "tok-ro", "x"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("只读角色写应 403，实际 %d", resp.StatusCode)
	}
	// R1 仅 t-b 作用域，写 t-a → 403（InScope 拒）
	if resp, _ := post(t, srv.URL, "/v1/evidence?tenant=t-a", "tok-tb", "x"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("越权租户写应 403，实际 %d", resp.StatusCode)
	}
}

// C-5 越权防线：即便用管理员身份，ref 段与 tenant 不符也须 403（防拿他租户 ref 蒙混）。
func TestEvidenceRefTenantMismatch(t *testing.T) {
	srv := newEvidServer(t)
	_, body := post(t, srv.URL, "/v1/evidence?tenant=t-a", "tok-admin", "secret-evidence")
	var out evidResp
	_ = json.Unmarshal([]byte(body), &out)
	// admin 作用域含 t-b，但 ref 属 t-a → 错配 403
	resp, rbody := get2(srv.URL+"/v1/evidence?tenant=t-b&ref="+out.Ref, "tok-admin")
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(rbody, "ref_tenant_mismatch") {
		t.Errorf("ref/tenant 错配应 403，实际 %d %s", resp.StatusCode, rbody)
	}
}

func TestEvidenceUnknownRef404(t *testing.T) {
	srv := newEvidServer(t)
	_, body := post(t, srv.URL, "/v1/evidence?tenant=t-a", "tok-admin", "e1")
	var out evidResp
	_ = json.Unmarshal([]byte(body), &out)
	missing := strings.TrimSuffix(out.Ref, ".bin") + "-nope.bin"
	resp, _ := get2(srv.URL+"/v1/evidence?tenant=t-a&ref="+missing, "tok-admin")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("未知 ref 应 404，实际 %d", resp.StatusCode)
	}
}
