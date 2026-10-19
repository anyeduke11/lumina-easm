package verifier

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
)

// 样例台账条目（最小合法形态；仅取 provider 请求面所需字段）。
func item() ledger.Item {
	return ledger.Item{ID: "L-2026-9", Tenant: "t-a", Phase: "P1", Title: "GitHub 令牌泄露",
		Asset: "hddata.cn", Level: "高", Source: "P1", Action: "删除"}
}

func okSandbox(t *testing.T, resp string, code int) (*Sandbox, *[]map[string]any) {
	t.Helper()
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		bodies = append(bodies, b)
		w.WriteHeader(code)
		_, _ = w.Write([]byte(resp))
	}))
	t.Cleanup(srv.Close)
	sb, err := NewSandbox(srv.URL)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}
	return sb, &bodies
}

// 为什么（ENH-10 前端接缝）：provider 产出是「权威验证记录」——reproduced 必须由沙箱
// 回执 evidence_ref 支撑（C-5）；调用方声明在 provider 面前无意义，不得透传冒充。
func TestSandboxReproducedCarriesEvidence(t *testing.T) {
	sb, bodies := okSandbox(t, `{"result":"reproduced","evidence_ref":"minio://sb/run-9.tar","verifier":"sb-vm-07"}`, 200)
	v, err := sb.VerifyItem(context.Background(), item())
	if err != nil {
		t.Fatal(err)
	}
	if v.Method != ledger.MethodSandbox {
		t.Errorf("方法应为 sandbox: %q", v.Method)
	}
	if v.Result != ledger.ResultReproduced || v.EvidenceRef != "minio://sb/run-9.tar" {
		t.Errorf("回执未被采纳: %+v", v)
	}
	if v.Verifier != "sb-vm-07" {
		t.Errorf("验证者应取沙箱回执标识: %q", v.Verifier)
	}
	if v.TS.IsZero() {
		t.Error("时间戳必须由 provider 盖章")
	}
	if len(*bodies) != 1 || (*bodies)[0]["item_id"] != "L-2026-9" || (*bodies)[0]["tenant"] != "t-a" {
		t.Errorf("请求应携带条目上下文: %+v", *bodies)
	}
}

// 为什么：无证据的「复现成功」=不可回溯的主张——provider 侧先行拒绝（纵深于 ledger.Validate 之前）。
func TestSandboxRejectsReproducedWithoutEvidence(t *testing.T) {
	sb, _ := okSandbox(t, `{"result":"reproduced"}`, 200)
	if _, err := sb.VerifyItem(context.Background(), item()); err == nil {
		t.Error("reproduced 无 evidence_ref 必须被 provider 拒绝")
	}
}

// 为什么：未知结果不得被静默归为 inconclusive——伪造第三态=污染验证记录（fail loud）。
func TestSandboxRejectsUnknownResult(t *testing.T) {
	sb, _ := okSandbox(t, `{"result":"maybe"}`, 200)
	if _, err := sb.VerifyItem(context.Background(), item()); err == nil || !strings.Contains(err.Error(), "result") {
		t.Errorf("未知 result 必须报错且提及 result: %v", err)
	}
}

// 为什么：refuted/inconclusive 不需要复现证据，但回执应被完整采纳（回退整改中）。
func TestSandboxRefutedPasses(t *testing.T) {
	sb, _ := okSandbox(t, `{"result":"refuted","note":"目标已下线"}`, 200)
	v, err := sb.VerifyItem(context.Background(), item())
	if err != nil {
		t.Fatal(err)
	}
	if v.Result != ledger.ResultRefuted || v.Note != "目标已下线" {
		t.Errorf("回执未被采纳: %+v", v)
	}
}

// 为什么：沙箱服务不可用必须上浮——装了 provider 却拿「调用失败」当「验证通过」=造假闭环。
func TestSandboxSurfacesTransportErrors(t *testing.T) {
	sb, _ := okSandbox(t, `{"error":"boom"}`, 500)
	if _, err := sb.VerifyItem(context.Background(), item()); err == nil {
		t.Error("非 200 回执必须上浮")
	}
	sb2, err := NewSandbox("http://127.0.0.1:1") // 无监听端口
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sb2.VerifyItem(context.Background(), item()); err == nil {
		t.Error("连接失败必须上浮")
	}
}

// 为什么：endpoint 配错必须装载即拒（fail loud），不得等第一次验证才暴露。
func TestNewSandboxValidatesEndpoint(t *testing.T) {
	for _, bad := range []string{"", "ftp://x", "127.0.0.1:9000"} {
		if _, err := NewSandbox(bad); err == nil {
			t.Errorf("非法 endpoint %q 应拒绝", bad)
		}
	}
}

// 为什么：ctx 取消必须可中断——沙箱复现可能数分钟，取消后不得继续占用执行面。
func TestSandboxRespectsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = w.Write([]byte(`{"result":"refuted"}`))
	}))
	defer srv.Close()
	sb, err := NewSandbox(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sb.VerifyItem(ctx, item()); !errors.Is(err, context.Canceled) {
		t.Errorf("ctx 取消应中断请求: %v", err)
	}
}
