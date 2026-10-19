// IR-11 监测与预警端点（F14 / FR-MON-001~004 近似版的 REST 面）。
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	if s.mon == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "monitor_unavailable", "监测预警未启用")
		return
	}
	items := s.mon.List(r.URL.Query().Get("kind"))
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func (s *Server) handleCreateMonitor(w http.ResponseWriter, r *http.Request) {
	if s.mon == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "monitor_unavailable", "监测预警未启用")
		return
	}
	if !principalOf(r).Can(rbac.PermManageTenants) { // 周期任务=平台级配置写
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无管理域权限")
		return
	}
	body, _ := io.ReadAll(r.Body)
	var in struct {
		Name        string `json:"name"`
		Kind        string `json:"kind"`
		IntervalSec int    `json:"interval_sec"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Name == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "name/kind/interval_sec 必填")
		return
	}
	if in.IntervalSec < 10 || in.IntervalSec > 604800 { // 下限防扫描风暴（NFR-AVL-002），上限 7 天
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "interval_sec 须在 10~604800")
		return
	}
	sp, err := s.mon.Add(in.Name, in.Kind, time.Duration(in.IntervalSec)*time.Second)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, sp)
}

// handleListMonitors 监控器 + 各自执行历史（FR-MON-001「可查询历史」）；events=内置导入事件流水。
func (s *Server) handleListMonitors(w http.ResponseWriter, r *http.Request) {
	if s.mon == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "monitor_unavailable", "监测预警未启用")
		return
	}
	type entry struct {
		Spec    any   `json:"spec"`
		History []any `json:"history"`
	}
	var items []entry
	for _, sp := range s.mon.Specs() {
		hs := s.mon.History(sp.ID)
		anyHis := make([]any, len(hs))
		for i, h := range hs {
			anyHis[i] = h
		}
		items = append(items, entry{Spec: sp, History: anyHis})
	}
	ev := s.mon.History(0)
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items), "events": ev})
}

func (s *Server) handleRunMonitor(w http.ResponseWriter, r *http.Request) {
	if s.mon == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "monitor_unavailable", "监测预警未启用")
		return
	}
	if !principalOf(r).Can(rbac.PermWriteAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无写入域权限")
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "id 须为数字")
		return
	}
	// 请求级可见面（主体作用域）扫描；cron 调度走平台全量 provider（main 装配）。
	n, err := s.mon.RunVisible(id, s.scopeAssets(r))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"new": n})
}
