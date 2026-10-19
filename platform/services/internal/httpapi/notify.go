// F14.4 告警统一出口端点（FR-MON-004）：dispatch 把当前告警流推送至配置通道（webhook/邮件），
// 通道未配置返回 501（能力边界显式化，禁止静默空发）。
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

func (s *Server) handleDispatchAlerts(w http.ResponseWriter, r *http.Request) {
	if s.mon == nil || s.notify == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "notify_unavailable", "告警出口未启用（配置 EASM_ALERT_WEBHOOK 或 EASM_ALERT_MAIL_TO）")
		return
	}
	if !principalOf(r).Can(rbac.PermNotify) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无通报权限")
		return
	}
	body, _ := io.ReadAll(r.Body)
	var in struct {
		Channel string `json:"channel"`
	}
	_ = json.Unmarshal(body, &in)
	if in.Channel == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "channel 必填（见 GET /v1/alerts/channels）")
		return
	}
	sent, skipped, err := s.notify.Dispatch(r.Context(), in.Channel, s.mon.List(""))
	if err != nil {
		writeError(w, requestIDOf(r), http.StatusUnprocessableEntity, "dispatch_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"channel": in.Channel, "sent": sent, "skipped_duplicate": skipped})
}

func (s *Server) handleNotifyChannels(w http.ResponseWriter, _ *http.Request) {
	if s.notify == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []string{}, "total": 0, "note": "未配置出口通道"})
		return
	}
	chs := s.notify.Channels()
	if chs == nil {
		chs = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": chs, "total": len(chs)})
}
