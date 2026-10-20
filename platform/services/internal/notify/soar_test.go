package notify

// M4-04 / WP-M4-04 SOAR 联动通道：告警以 HMAC-SHA256 签名 POST 到 SOAR 编排平台，
// 接收侧可验签防伪造（告警=响应动作的触发源，伪造=诱导 SOAR 自动处置，必须签名）。
// 复用统一出口三闸门（只推高危/去重/失败上浮）——SOAR 只是新增 Sender，无特权路径。

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
)

func TestSOARSignsPayloadAndFilters(t *testing.T) {
	const secret = "soar-shared-secret"
	var gotSig string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-EASM-Signature")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := New()
	s.AddChannel("soar", SOAR(srv.URL, secret))
	// 高危=推送且签名可复算；低危=出口闸门过滤不推（纵深防御）
	sent, skipped, err := s.Dispatch(context.Background(), "soar", []monitor.Alert{
		{Key: "k-high", Kind: "vuln_match", TenantID: "t-a", Severity: "high", Msg: "高危", TS: time.Now().UTC()},
		{Key: "k-low", Kind: "vuln_match", TenantID: "t-a", Severity: "low", Msg: "低危", TS: time.Now().UTC()},
	})
	if err != nil || sent != 1 || skipped != 0 {
		t.Fatalf("SOAR 派发: sent=%d skipped=%d err=%v", sent, skipped, err)
	}
	if !strings.HasPrefix(gotSig, "sha256=") {
		t.Fatalf("缺签名头: %q", gotSig)
	}
	want := hmacSHA256Hex(secret, gotBody)
	if gotSig != "sha256="+want {
		t.Fatalf("签名不可复算: got=%q want=%q", gotSig, want)
	}
	if !strings.Contains(string(gotBody), `"kind":"easm_soar_event"`) {
		t.Fatalf("payload 形状错误: %s", gotBody)
	}
}

func TestSOARRejectsTamperedBody(t *testing.T) {
	// 为什么：接收侧验签用原始 body——若实现先签名后改写 body，验签必失败=联调事故
	const secret = "s2"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sig := r.Header.Get("X-EASM-Signature")
		if sig != "sha256="+hmacSHA256Hex(secret, body) {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	s := New()
	s.AddChannel("soar", SOAR(srv.URL, secret))
	_, _, err := s.Dispatch(context.Background(), "soar", []monitor.Alert{
		{Key: "k1", TenantID: "t-a", Severity: "critical", Msg: "m", TS: time.Now()},
	})
	if err != nil {
		t.Fatalf("自洽签名应通过: %v", err)
	}
}

func TestSOARFailureSurfaces(t *testing.T) {
	// 闸门③：接收端 5xx=失败上浮且不记已送（下轮重试），禁止静默丢失
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	s := New()
	s.AddChannel("soar", SOAR(srv.URL, "k"))
	_, _, err := s.Dispatch(context.Background(), "soar", []monitor.Alert{
		{Key: "k1", TenantID: "t-a", Severity: "high", TS: time.Now()},
	})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("SOAR 失败应上浮: %v", err)
	}
}

func hmacSHA256Hex(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
