// Package notify 实现告警统一出口（F14.4 / FR-MON-004「统一出口+无重复推送」）：
// Webhook（钉钉/飞书机器人同为 webhook 形态）与 SMTP 两类通用通道；
// 出口层三闸门——①只推高危（纵深防御，不信任调用方过滤）②按 通道|告警Key 去重
// ③发送失败一律上浮（禁止静默丢失=监管链路断点，fail loud）。
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/smtp"
	"os"
	"sync"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
)

var ErrNoChannel = errors.New("notify: 通道不存在")

// Sender 通道执行器（测试注入 fake；生产 Webhook/SMTPSender 两实现）。
type Sender func(ctx context.Context, a monitor.Alert) error

// LogStore 发送历史端口（009_notify_log.sql）：keys=完整去重键「channel|alertKey」。
// AttachLog 后：① hydrate 已推集（跨重启不重推，FR-MON-004）② 每轮成功推送追加留痕。
type LogStore interface {
	LogDispatch(channel string, keys []string) error
	LoadedKeys(channel string) ([]string, error)
}

type Service struct {
	mu    sync.Mutex
	chans map[string]Sender
	sent  map[string]bool // 通道|Key 出口去重（FR-MON-004）
	log   LogStore        // nil=仅内存去重（测试/无 PG）
}

func New() *Service {
	return &Service{chans: map[string]Sender{}, sent: map[string]bool{}}
}

// AttachLog 接上历史源并 hydrate 各通道已推集（须在 AddChannel 之后调用）。
func (s *Service) AttachLog(l LogStore) error {
	s.mu.Lock()
	s.log = l
	var chans []string
	for c := range s.chans {
		chans = append(chans, c)
	}
	s.mu.Unlock()
	for _, c := range chans {
		ks, err := l.LoadedKeys(c)
		if err != nil {
			return err
		}
		s.mu.Lock()
		for _, k := range ks {
			s.sent[k] = true
		}
		s.mu.Unlock()
	}
	return nil
}

func (s *Service) AddChannel(name string, snd Sender) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chans[name] = snd
}

func (s *Service) Channels() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k := range s.chans {
		out = append(out, k)
	}
	return out
}

// Dispatch 向指定通道推送告警集：非高危过滤、已推去重、失败即返（已送出计数仍返回供审计）。
func (s *Service) Dispatch(ctx context.Context, channel string, alerts []monitor.Alert) (sent, skipped int, err error) {
	s.mu.Lock()
	snd, ok := s.chans[channel]
	s.mu.Unlock()
	if !ok {
		return 0, 0, fmt.Errorf("%w: %s", ErrNoChannel, channel)
	}
	var doneKeys []string
	for _, a := range alerts {
		if a.Severity != "critical" && a.Severity != "high" { // 闸门①：纵深防御二次过滤
			continue
		}
		key := channel + "|" + a.Key
		s.mu.Lock()
		dup := s.sent[key]
		s.mu.Unlock()
		if dup { // 闸门②：无重复推送
			skipped++
			continue
		}
		if err = snd(ctx, a); err != nil { // 闸门③：失败上浮且不记已送（下轮可重试）
			return sent, skipped, fmt.Errorf("notify: 通道 %s 发送失败: %w", channel, err)
		}
		s.mu.Lock()
		s.sent[key] = true
		s.mu.Unlock()
		doneKeys = append(doneKeys, key)
		sent++
	}
	if l := s.log; l != nil && len(doneKeys) > 0 { // 留痕（历史失败上浮=可观测的断链，不静默）
		if err := l.LogDispatch(channel, doneKeys); err != nil {
			return sent, skipped, fmt.Errorf("notify: 发送历史留痕失败: %w", err)
		}
	}
	return sent, skipped, nil
}

// ---- Webhook 通道 ----

// Webhook POST JSON（kind=easm_alert；钉钉/飞书机器人可在接收侧适配或直连本形状）。
func Webhook(url string) Sender {
	cli := &http.Client{Timeout: 10 * time.Second}
	return func(ctx context.Context, a monitor.Alert) error {
		body, _ := json.Marshal(map[string]any{
			"kind": "easm_alert", "alert_key": a.Key, "alert_kind": a.Kind,
			"ref": a.Ref, "severity": a.Severity, "confidence": a.Confidence,
			"asset_id": a.AssetID, "asset_name": a.AssetName, "msg": a.Msg, "ts": a.TS,
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := cli.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("webhook %s 返回 %d", url, resp.StatusCode)
		}
		return nil
	}
}

// ---- SMTP 通道 ----

// SMTPSender 构造邮件通道；send=nil 时用真实 SMTP（host 取 EASM_SMTP_HOST，如 "mail.corp:587"）。
func SMTPSender(from, to string, send func(from, to string, msg []byte) error) Sender {
	if send == nil {
		host := os.Getenv("EASM_SMTP_HOST")
		if host == "" {
			host = "127.0.0.1:25"
		}
		send = func(f, t string, m []byte) error { return smtp.SendMail(host, nil, f, []string{t}, m) }
	}
	return func(_ context.Context, a monitor.Alert) error {
		msg := []byte("From: " + from + "\r\n" +
			"To: " + to + "\r\n" +
			"Subject: [EASM] 高危告警 " + a.Key + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/plain; charset=UTF-8\r\n" +
			"Content-Transfer-Encoding: 8bit\r\n\r\n" +
			a.Msg + "\r\n对象: " + a.Ref + " / 资产: " + a.AssetName +
			"\r\n\r\n—— EASM 统一告警出口（FR-MON-004）\r\n")
		return send(from, to, msg)
	}
}
