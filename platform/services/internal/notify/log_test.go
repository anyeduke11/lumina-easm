package notify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
)

// 为什么（009 / 批四「跨重启」同型原则）：出口去重集若只在内存，server 重启即可重复
// 推送同一告警=FR-MON-004「无重复推送」在重启边界失效；发送历史还必须可审计
// （谁于何时把哪条告警推到了哪个通道——监管链路留痕）。

type fakeLog struct {
	calls map[string][]string
}

func newFakeLog() *fakeLog { return &fakeLog{calls: map[string][]string{}} }

func (f *fakeLog) LogDispatch(channel string, keys []string) error {
	f.calls[channel] = append(f.calls[channel], keys...)
	return nil
}
func (f *fakeLog) LoadedKeys(channel string) ([]string, error) { return f.calls[channel], nil }

func a(k string) monitor.Alert {
	return monitor.Alert{Key: k, Kind: "vuln_match", Ref: "CVE-1", Severity: "critical",
		Confidence: 0.9, Msg: "m " + k}
}

func TestAttachLogHydratesDedupAcrossRestart(t *testing.T) {
	var got int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	fl := newFakeLog()

	s1 := New()
	s1.AddChannel("ops", Webhook(srv.URL))
	if err := s1.AttachLog(fl); err != nil {
		t.Fatal(err)
	}
	if sent, _, err := s1.Dispatch(context.Background(), "ops", []monitor.Alert{a("k1"), a("k2")}); err != nil || sent != 2 {
		t.Fatalf("首推 2: %v %d", err, sent)
	}
	// 「重启」：新 Service + 同历史源 → 已推 key 必须继续去重
	s2 := New()
	s2.AddChannel("ops", Webhook(srv.URL))
	if err := s2.AttachLog(fl); err != nil {
		t.Fatal(err)
	}
	sent, skipped, err := s2.Dispatch(context.Background(), "ops", []monitor.Alert{a("k1"), a("k2"), a("k3")})
	if err != nil || sent != 1 || skipped != 2 {
		t.Errorf("跨重启去重失败: sent=%d skipped=%d err=%v", sent, skipped, err)
	}
	if got != 3 { // 真实网络只收到 3 次（k1 k2 k3 各一）——重启未导致重推
		t.Errorf("通道实际收到 %d 次，应 3（跨重启重复推送）", got)
	}
	if strings.Join(fl.calls["ops"], ",") != "ops|k1,ops|k2,ops|k3" {
		t.Errorf("历史留痕错误: %v", fl.calls)
	}
}

// 发送失败不得记历史（否则重启后该告警被「假已推」吞掉——静默丢失）。
func TestFailedSendNotLogged(t *testing.T) {
	fl := newFakeLog()
	s := New()
	s.AddChannel("bad", Webhook("http://127.0.0.1:1/nope"))
	_ = s.AttachLog(fl)
	if _, _, err := s.Dispatch(context.Background(), "bad", []monitor.Alert{a("k9")}); err == nil {
		t.Fatal("应报错")
	}
	if len(fl.calls["bad"]) != 0 {
		t.Errorf("失败不得入历史: %v", fl.calls)
	}
	if s.sent["bad|k9"] {
		t.Error("失败不得入内存去重集（下轮须可重试）")
	}
}

type errLog struct{ fakeLog }

func (e *errLog) LogDispatch(string, []string) error { return errors.New("audit db down") }

// 历史写入失败必须上浮（留痕断链不可静默——人工介入判定是否补推）。
func TestLogFailureLoud(t *testing.T) {
	var got int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	s := New()
	s.AddChannel("c", Webhook(srv.URL))
	if err := s.AttachLog(&errLog{fakeLog{calls: map[string][]string{}}}); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.Dispatch(context.Background(), "c", []monitor.Alert{a("k1")})
	if err == nil || !strings.Contains(err.Error(), "audit db down") {
		t.Fatalf("历史失败应上浮: %v", err)
	}
	if got != 1 {
		t.Errorf("推送本身已发生应恰好 1 次，实际 %d", got)
	}
	// 同进程内仍视为已推（内存去重在先，避免重复外发；留痕缺口由错误上浮暴露）
	sent2, sk2, _ := s.Dispatch(context.Background(), "c", []monitor.Alert{a("k1")})
	if sent2 != 0 || sk2 != 1 {
		t.Errorf("同进程去重应保持: sent=%d skipped=%d", sent2, sk2)
	}
}
