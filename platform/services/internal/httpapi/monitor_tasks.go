package httpapi

// M4-03 / FR-MON-003 排查任务单出口：触发→生成任务单、可查询、可人工完成（AX-5）。
// 路由：GET /v1/tenants/{id}/monitors/tasks、POST /v1/tenants/{id}/monitors/tasks:poc、
// POST /v1/tenants/{id}/monitors/tasks/{tid}/done。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// handleMonitorTasksList GET /v1/tenants/{id}/monitors/tasks?status=
func (s *Server) handleMonitorTasksList(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	if !p.Can(rbac.PermReadAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无读取权限")
		return
	}
	tid := r.PathValue("id")
	if _, err := s.tenants.Get(r.Context(), p, requestIDOf(r), tid); err != nil {
		failFrom(w, r, err)
		return
	}
	ts, err := s.mon.Tasks(r.Context(), tid, r.URL.Query().Get("status"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	if ts == nil {
		ts = []monitor.Task{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": tid, "total": len(ts), "tasks": ts,
		"basis": "FR-MON-003：资产新增/变更/新 POC 触发→排查任务单；同源未闭环单收敛刷新；完成须人工（AX-5）",
	})
}

// handleMonitorTasksPoc POST /v1/tenants/{id}/monitors/tasks:poc
// 新 POC/CVE 发布入口：影响面资产（或空=全租户）→ 排查任务单。
func (s *Server) handleMonitorTasksPoc(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	if !p.Can(rbac.PermWriteAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无写入权限")
		return
	}
	tid := r.PathValue("id")
	if _, err := s.tenants.Get(r.Context(), p, requestIDOf(r), tid); err != nil {
		failFrom(w, r, err)
		return
	}
	var in struct {
		CVE    string   `json:"cve"`
		Assets []string `json:"asset_ids"` // 空=租户级全量重扫
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if in.CVE == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "cve 必填")
		return
	}
	affected, err := s.monitorAssetsForPOC(r.Context(), p, requestIDOf(r), tid, in.Assets)
	if err != nil {
		// 影响面资产不存在/越权=请求方指定错误（400），不是服务端故障
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.mon.OnNewPOC(r.Context(), tid, in.CVE, affected); err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": tid, "cve": in.CVE, "affected": len(affected),
		"basis": "FR-MON-003：新 POC/CVE 发布→受影响资产排查任务单（空=租户级）；同源未闭环幂等",
	})
}

// handleMonitorTaskDone POST /v1/tenants/{id}/monitors/tasks/{tid}/done
func (s *Server) handleMonitorTaskDone(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	if !p.Can(rbac.PermWriteAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无写入权限")
		return
	}
	tid := r.PathValue("id")
	if _, err := s.tenants.Get(r.Context(), p, requestIDOf(r), tid); err != nil {
		failFrom(w, r, err)
		return
	}
	var in struct {
		By   string `json:"by"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	tk, err := s.mon.TaskDone(r.Context(), tid, r.PathValue("tid"), in.By, in.Note)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": tid, "task": tk,
		"basis": "人工确认闭环（AX-5）；终态不得重复虚报（409 task_closed）",
	})
}

// monitorAssetsForPOC 解析 asset_ids → 租户内在账资产（越权/不存在 ID 拒绝触发，fail loud；
// 不猜影响面）。ids 空=租户级（OnNewPOC 内部落 tenant 级任务单）。
func (s *Server) monitorAssetsForPOC(ctx context.Context, p rbac.Principal, requestID, tid string, ids []string) ([]asset.Asset, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	all, err := s.assets.ListByTenant(ctx, p, requestID, tid)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]asset.Asset, len(all))
	for _, a := range all {
		byID[a.ID] = a
	}
	out := make([]asset.Asset, 0, len(ids))
	for _, id := range ids {
		a, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("asset %s 不存在或不在租户 %s 内（拒绝猜测影响面）", id, tid)
		}
		out = append(out, a)
	}
	return out, nil
}
