// httpapi/easm.go — Phase 1 EASM 核心端点：观察流 / 资产 / Finding / Job。
package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/alert"
	"github.com/wangdev88/easm-platform/platform/services/internal/finding"
	"github.com/wangdev88/easm-platform/platform/services/internal/inventory"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

type observationInput struct {
	Kind       string            `json:"kind"`
	Value      string            `json:"value"`
	SourceID   string            `json:"source_id"`
	RawRef     string            `json:"raw_ref,omitempty"`
	Payload    map[string]string `json:"payload,omitempty"`
	ObservedAt time.Time         `json:"observed_at,omitempty"`
}

func (s *Server) requireEntity(w http.ResponseWriter, r *http.Request, eid string) bool {
	if s.tenants == nil {
		return true
	}
	if _, err := s.tenants.Get(r.Context(), principalOf(r), requestIDOf(r), eid); err != nil {
		failFrom(w, r, err)
		return false
	}
	return true
}

func (s *Server) handleIngestObservation(w http.ResponseWriter, r *http.Request) {
	if s.inventory == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "inventory_unavailable", "资产身份服务未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermWriteAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	if !s.requireEntity(w, r, eid) {
		return
	}
	var in observationInput
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if strings.TrimSpace(in.SourceID) == "" {
		in.SourceID = "manual"
	}
	a, created, err := s.inventory.Ingest(r.Context(), eid, inventory.Observation{
		Kind: in.Kind, Value: in.Value, SourceID: in.SourceID,
		RawRef: in.RawRef, Payload: in.Payload, ObservedAt: in.ObservedAt,
	})
	if err != nil {
		failFrom(w, r, err)
		return
	}
	findingCount := 0
	if s.detector != nil {
		fs, err := s.detector.Observe(r.Context(), a, inventory.Observation{
			Kind: in.Kind, Value: in.Value, SourceID: in.SourceID,
			RawRef: in.RawRef, Payload: in.Payload, ObservedAt: in.ObservedAt,
		})
		if err != nil {
			failFrom(w, r, err)
			return
		}
		findingCount = len(fs)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"asset": a, "created": created, "findings": findingCount})
}

func (s *Server) handleListInventory(w http.ResponseWriter, r *http.Request) {
	if s.inventory == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "inventory_unavailable", "资产身份服务未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermReadAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	out, err := s.inventory.List(r.Context(), eid, limitParam(r, 100))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"assets": out, "count": len(out)})
}

func (s *Server) handleGetInventoryAsset(w http.ResponseWriter, r *http.Request) {
	if s.inventory == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "inventory_unavailable", "资产身份服务未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermReadAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	a, err := s.inventory.Get(r.Context(), eid, r.PathValue("aid"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleInventoryObservations(w http.ResponseWriter, r *http.Request) {
	if s.inventory == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "inventory_unavailable", "资产身份服务未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermReadAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	out, err := s.inventory.Observations(r.Context(), eid, r.PathValue("aid"), limitParam(r, 100))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"observations": out, "count": len(out)})
}

type stateInput struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

func (s *Server) handleSetInventoryState(w http.ResponseWriter, r *http.Request) {
	if s.inventory == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "inventory_unavailable", "资产身份服务未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermWriteAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	if !s.requireEntity(w, r, eid) {
		return
	}
	var in stateInput
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	out, err := s.inventory.SetState(r.Context(), eid, r.PathValue("aid"), in.State, in.Reason, p.UserID)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type discoveryInput struct {
	Connector string   `json:"connector"`
	Seeds     []string `json:"seeds"`
}

func (s *Server) handleStartDiscovery(w http.ResponseWriter, r *http.Request) {
	if s.discovery == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "discovery_unavailable", "发现编排未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermWriteAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	if !s.requireEntity(w, r, eid) {
		return
	}
	var in discoveryInput
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	j, err := s.discovery.Enqueue(r.Context(), eid, in.Connector, in.Seeds)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, j)
}

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	if s.jobs == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "jobs_unavailable", "任务队列未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermReadAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	out, err := s.jobs.List(r.Context(), eid, r.URL.Query().Get("state"), limitParam(r, 100))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": out, "count": len(out)})
}

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	if s.jobs == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "jobs_unavailable", "任务队列未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermWriteAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	j, err := s.jobs.Get(r.Context(), r.PathValue("jid"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	if j.EntityID != eid {
		writeError(w, requestIDOf(r), http.StatusNotFound, "not_found", "job not found")
		return
	}
	out, err := s.jobs.Cancel(r.Context(), j.ID)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateFinding(w http.ResponseWriter, r *http.Request) {
	if s.findings == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "findings_unavailable", "Finding 服务未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermWriteAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	if !s.requireEntity(w, r, eid) {
		return
	}
	var in finding.Finding
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	in.EntityID, in.ID = eid, ""
	out, err := s.findings.Create(r.Context(), in)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	if s.alerts != nil && (out.Severity == "high" || out.Severity == "critical") {
		if _, err := s.alerts.Raise(r.Context(), alert.Alert{
			EntityID: out.EntityID, FindingID: out.ID, Severity: out.Severity,
			Title: out.Title, Source: out.Source,
		}); err != nil {
			failFrom(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	if s.findings == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "findings_unavailable", "Finding 服务未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermReadAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	out, err := s.findings.List(r.Context(), eid, r.URL.Query().Get("lifecycle"), limitParam(r, 100))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": out, "count": len(out)})
}

func (s *Server) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	if s.findings == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "findings_unavailable", "Finding 服务未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermReadAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	f, err := s.findings.Get(r.Context(), eid, r.PathValue("fid"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, f)
}

type validationInput struct {
	Method      string `json:"method"`
	Result      string `json:"result"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
	Note        string `json:"note,omitempty"`
}

func (s *Server) handleValidateFinding(w http.ResponseWriter, r *http.Request) {
	if s.findings == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "findings_unavailable", "Finding 服务未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermWriteAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	var in validationInput
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	out, err := s.findings.Validate(r.Context(), eid, r.PathValue("fid"), p.UserID, finding.Validation{
		Method: in.Method, Result: in.Result, EvidenceRef: in.EvidenceRef, Note: in.Note,
	})
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type closeInput struct {
	Note string `json:"note,omitempty"`
}

func (s *Server) handleCloseFinding(w http.ResponseWriter, r *http.Request) {
	if s.findings == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "findings_unavailable", "Finding 服务未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermWriteAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	var in closeInput
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in)
	out, err := s.findings.Close(r.Context(), eid, r.PathValue("fid"), p.UserID, in.Note)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type bulkFindingInput struct {
	Action      string   `json:"action"`
	IDs         []string `json:"ids"`
	EvidenceRef string   `json:"evidence_ref,omitempty"`
	Note        string   `json:"note,omitempty"`
}

func (s *Server) handleBulkFindings(w http.ResponseWriter, r *http.Request) {
	if s.findings == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "findings_unavailable", "Finding 服务未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermWriteAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	var in bulkFindingInput
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if len(in.IDs) == 0 || len(in.IDs) > 200 {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "ids 必须为 1..200")
		return
	}
	if in.Action != "confirm" && in.Action != "close" && in.Action != "project" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "action 须为 confirm/close/project")
		return
	}
	if in.Action == "project" && s.projector == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "projection_unavailable", "台账投影未启用")
		return
	}
	failed := make([]map[string]string, 0)
	ok := 0
	for _, id := range in.IDs {
		var err error
		switch in.Action {
		case "confirm":
			_, err = s.findings.Validate(r.Context(), eid, id, p.UserID, finding.Validation{
				Method: "manual", Result: finding.ResultConfirmed, EvidenceRef: in.EvidenceRef, Note: in.Note,
			})
		case "close":
			_, err = s.findings.Close(r.Context(), eid, id, p.UserID, in.Note)
		case "project":
			var f finding.Finding
			f, err = s.findings.Get(r.Context(), eid, id)
			if err == nil {
				_, err = s.projector.Project(r.Context(), p, f)
			}
		}
		if err != nil {
			failed = append(failed, map[string]string{"id": id, "error": err.Error()})
			continue
		}
		ok++
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "failed": failed, "action": in.Action})
}

func (s *Server) handleListFindingAlerts(w http.ResponseWriter, r *http.Request) {
	if s.alerts == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "alerts_unavailable", "告警服务未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermReadAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	out, err := s.alerts.List(r.Context(), eid, r.URL.Query().Get("status"), limitParam(r, 100))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": out, "count": len(out)})
}

func (s *Server) handleDispatchFindingAlerts(w http.ResponseWriter, r *http.Request) {
	if s.alerts == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "alerts_unavailable", "告警服务未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermWriteAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	var in struct {
		Channel string `json:"channel"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil || in.Channel == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "channel 必填")
		return
	}
	sent, skipped, err := s.alerts.Dispatch(r.Context(), eid, in.Channel)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sent": sent, "skipped": skipped, "channel": in.Channel})
}

func (s *Server) handleAckAlert(w http.ResponseWriter, r *http.Request) {
	if s.alerts == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "alerts_unavailable", "告警服务未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermWriteAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	out, err := s.alerts.Ack(r.Context(), eid, r.PathValue("aid"), p.UserID)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleProjectFinding(w http.ResponseWriter, r *http.Request) {
	if s.findings == nil || s.projector == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "projection_unavailable", "Finding/台账投影未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermWriteAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	f, err := s.findings.Get(r.Context(), eid, r.PathValue("fid"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	item, err := s.projector.Project(r.Context(), p, f)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleDecayInventory(w http.ResponseWriter, r *http.Request) {
	if s.inventory == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "inventory_unavailable", "资产身份服务未启用")
		return
	}
	eid := r.PathValue("id")
	p := principalOf(r)
	if !p.InScope(eid) {
		failFrom(w, r, rbac.ErrCrossTenant)
		return
	}
	if !p.Can(rbac.PermWriteAssets) {
		failFrom(w, r, rbac.ErrForbidden)
		return
	}
	if !s.requireEntity(w, r, eid) {
		return
	}
	var in struct {
		StaleAfterHours  int `json:"stale_after_hours"`
		RetireAfterHours int `json:"retire_after_hours"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in)
	stale, retire := s.assetStale, s.assetRetire
	if stale <= 0 {
		stale = 720 * time.Hour
	}
	if retire <= 0 {
		retire = 2160 * time.Hour
	}
	if in.StaleAfterHours > 0 {
		stale = time.Duration(in.StaleAfterHours) * time.Hour
	}
	if in.RetireAfterHours > 0 {
		retire = time.Duration(in.RetireAfterHours) * time.Hour
	}
	n, err := s.inventory.Decay(r.Context(), eid, stale, retire, p.UserID)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"decayed": n, "stale_after_hours": int(stale.Hours()), "retire_after_hours": int(retire.Hours())})
}

func limitParam(r *http.Request, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 500 {
		return v
	}
	return def
}
