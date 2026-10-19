package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
)

// 为什么（FR-MON-004 / PRD F14.4 统一出口）：告警必须经统一通道出口且「无重复推送」；
// 出口失败必须上浮（fail loud）——静默丢失=监管链路断点，比不发更危险。
func alert(k, sev string) monitor.Alert {
	return monitor.Alert{Key: k, Kind: "vuln_match", Ref: "CVE-2026-1", Severity: sev,
		Confidence: 0.9, Msg: "Redis 未授权命中 cache.a.cn", AssetID: "a1", AssetName: "cache.a.cn"}
}

func TestWebhookDispatch(t *testing.T) {
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	s := New()
	s.AddChannel("ops", Webhook(srv.URL))
	sent, skipped, err := s.Dispatch(context.Background(), "ops", []monitor.Alert{alert("vuln_match|CVE-2026-1|a1", "critical")})
	if err != nil || sent != 1 || skipped != 0 {
		t.Fatalf("首推应 sent=1: %v %d %d", err, sent, skipped)
	}
	var payload map[string]any
	if err := json.Unmarshal(got, &payload); err != nil {
		t.Fatalf("webhook 体非 JSON: %s", got)
	}
	if payload["kind"] != "easm_alert" || !strings.Contains(string(got), "CVE-2026-1") {
		t.Errorf("payload 字段错误: %s", got)
	}
}

// 去重=FR-MON-004 验收核心（守卫点：重复推送即监管噪声/漏账）。
func TestDispatchDedup(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	s := New()
	s.AddChannel("c", Webhook(srv.URL))
	a := []monitor.Alert{alert("k1", "critical"), alert("k2", "high")}
	if sent, _, err := s.Dispatch(context.Background(), "c", a); err != nil || sent != 2 {
		t.Fatal(sent, err)
	}
	sent2, skipped2, err := s.Dispatch(context.Background(), "c", a)
	if err != nil || sent2 != 0 || skipped2 != 2 {
		t.Errorf("重放不得重复推送: sent=%d skipped=%d err=%v", sent2, skipped2, err)
	}
	if n != 2 {
		t.Errorf("通道实际收到 %d 次，应 2（出口去重被绕过）", n)
	}
}

// 纵深防御：通道层二次强制「只推高危」——即便调用方传入非高危也不外发。
func TestHighRiskOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	s := New()
	s.AddChannel("c", Webhook(srv.URL))
	sent, _, err := s.Dispatch(context.Background(), "c", []monitor.Alert{alert("k1", "medium"), alert("k2", "low")})
	if err != nil || sent != 0 {
		t.Errorf("medium/low 不得外发: sent=%d %v", sent, err)
	}
}

func TestChannelFailureLoud(t *testing.T) {
	s := New()
	s.AddChannel("bad", Webhook("http://127.0.0.1:1/nope")) // 必连败
	_, _, err := s.Dispatch(context.Background(), "bad", []monitor.Alert{alert("k1", "critical")})
	if err == nil {
		t.Fatal("通道失败必须上浮（禁止静默丢失）")
	}
	if _, _, err := s.Dispatch(context.Background(), "nosuch", nil); !errors.Is(err, ErrNoChannel) {
		t.Errorf("未知通道应报 ErrNoChannel: %v", err)
	}
}

// SMTP：消息构造正确 + 失败上浮（sender 注入，不真连外网）。
func TestSMTPMessageAndFailure(t *testing.T) {
	var last string
	s := New()
	s.AddChannel("mail", SMTPSender("easm@corp.cn", "sec@corp.cn", func(from, to string, msg []byte) error {
		last = string(msg)
		return nil
	}))
	if _, _, err := s.Dispatch(context.Background(), "mail", []monitor.Alert{alert("k1", "high")}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(last, "Subject: [EASM] 高危告警 k1") || !strings.Contains(last, "CVE-2026-1") || !strings.Contains(last, "From: easm@corp.cn") {
		t.Errorf("邮件正文错误: %q", last)
	}
	s.AddChannel("mailbad", SMTPSender("a@b.c", "d@e.f", func(_, _ string, _ []byte) error { return errors.New("smtp down") }))
	if _, _, err := s.Dispatch(context.Background(), "mailbad", []monitor.Alert{alert("k9", "critical")}); err == nil {
		t.Error("SMTP 失败必须上浮")
	}
}
