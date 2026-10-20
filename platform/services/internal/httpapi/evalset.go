package httpapi

// M3-E 评测集与反馈门禁出口（WP-M3-06 / FR-VRF-004 / AIL-7）。
// 七个端点：样本导入/列举、二次标注、台账回流、评测运行、运行历史、门禁检查。
// 未装配=501 eval_unavailable（不半可用）；写面 PermWriteAssets、读面 PermReadAssets。

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/wangdev88/easm-platform/platform/services/internal/evalset"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

func (s *Server) evalReady() bool { return s.evals != nil }

// handleEvalSamplesList GET /v1/tenants/{id}/evalset/samples
func (s *Server) handleEvalSamplesList(w http.ResponseWriter, r *http.Request) {
	if !s.evalReady() {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "eval_unavailable", "评测集未装配")
		return
	}
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
	ss, err := s.evals.Samples(r.Context(), tid)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	if ss == nil {
		ss = []evalset.Sample{}
	}
	th, thSrc := s.evals.ThresholdInfo()
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": tid, "total": len(ss), "samples": ss,
		"thresholds": th, "threshold_source": thSrc,
		"basis": "评测集骨架（M3-E）：判敏样本 → 指标（F1/κ/误报率/幻觉率）→ 放量门禁（AIL-7）",
	})
}

// handleEvalSamplesAdd POST /v1/tenants/{id}/evalset/samples
func (s *Server) handleEvalSamplesAdd(w http.ResponseWriter, r *http.Request) {
	if !s.evalReady() {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "eval_unavailable", "评测集未装配")
		return
	}
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
		Samples []evalset.SampleInput `json:"samples"`
		By      string                `json:"by"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if len(in.Samples) == 0 {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "samples 不可为空")
		return
	}
	added, out, err := s.evals.AddSamples(r.Context(), tid, in.Samples, in.By)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": tid, "added": added, "samples": out,
		"basis": "同租户同文本同期望=同一样本（确定性 ID），重放幂等",
	})
}

// handleEvalRelabel POST /v1/tenants/{id}/evalset/relabel
func (s *Server) handleEvalRelabel(w http.ResponseWriter, r *http.Request) {
	if !s.evalReady() {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "eval_unavailable", "评测集未装配")
		return
	}
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
		SampleID string `json:"sample_id"`
		Expected *bool  `json:"expected"`
		Note     string `json:"note"`
		By       string `json:"by"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if in.SampleID == "" || in.Expected == nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "sample_id 与 expected 必填")
		return
	}
	sm, err := s.evals.Relabel(r.Context(), tid, in.SampleID, in.By, *in.Expected, in.Note)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": tid, "sample": sm,
		"basis": "二次标注追加式（κ=标注一致性的第二评分者），不改写历史标注",
	})
}

// handleEvalReflux POST /v1/tenants/{id}/evalset/reflux
func (s *Server) handleEvalReflux(w http.ResponseWriter, r *http.Request) {
	if !s.evalReady() {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "eval_unavailable", "评测集未装配")
		return
	}
	if s.ledger == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "ledger_unavailable", "台账未装配，回流不可用")
		return
	}
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
		By string `json:"by"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	// 主体作用域过滤在 ledger.List 内完成（越权条目不回流）；Service 层再按租户二次校验
	items, err := s.ledger.List(r.Context(), p, requestIDOf(r), ledger.Filter{Tenant: tid})
	if err != nil {
		failFrom(w, r, err)
		return
	}
	res, err := s.evals.Reflux(r.Context(), tid, items, in.By)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": tid, "ledger_items": len(items), "added": res.Added,
		"samples": res.Samples, "skipped": res.Skipped,
		"basis": "FR-VRF-004 误报回流：反证成立/复测 refuted → 误报样本；最近复测 reproduced → 真阳性样本；无信号跳过留痕（不猜标签）",
	})
}

// handleEvalRun POST /v1/tenants/{id}/evalset:run
func (s *Server) handleEvalRun(w http.ResponseWriter, r *http.Request) {
	if !s.evalReady() {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "eval_unavailable", "评测集未装配")
		return
	}
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
	// 骨架期唯一装配对象=确定性判敏引擎（AX-2）；AI 面经 Subject 接缝替换（ENH-03）
	run, err := s.evals.Run(r.Context(), tid, evalset.NewClassifySubject(s.cls))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"run": run})
}

// handleEvalPromote POST /v1/tenants/{id}/evalset/promote
// 灰度放量动作面（AIL-7 执行点）：消费门禁判定——未放行 403（理由随行）；
// 放行落留痕（谁在哪个 run 下放量+阈值口径快照，020 落库可审计）。
func (s *Server) handleEvalPromote(w http.ResponseWriter, r *http.Request) {
	if !s.evalReady() {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "eval_unavailable", "评测集未装配")
		return
	}
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
	promote, d, err := s.evals.Promote(r.Context(), tid, in.By, in.Note)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": tid, "promote": promote, "gate": d,
		"basis": "放量动作已按门禁判定放行并留痕（run_id=放行依据；thresholds=放行时口径快照，换配置前后可对账）",
	})
}

// handleEvalRuns GET /v1/tenants/{id}/evalset/runs
func (s *Server) handleEvalRuns(w http.ResponseWriter, r *http.Request) {
	if !s.evalReady() {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "eval_unavailable", "评测集未装配")
		return
	}
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
	rs, err := s.evals.Runs(r.Context(), tid, 20)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	if rs == nil {
		rs = []evalset.Run{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant": tid, "total": len(rs), "runs": rs})
}

// handleEvalGate GET /v1/tenants/{id}/evalset/gate
func (s *Server) handleEvalGate(w http.ResponseWriter, r *http.Request) {
	if !s.evalReady() {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "eval_unavailable", "评测集未装配")
		return
	}
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
	run, d, err := s.evals.Check(r.Context(), tid)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": tid, "latest_run": run, "gate": d,
		"basis": "指标不达标不放量（AIL-7/WP-M3-06）；无评测记录 fail closed；gate 按当前阈值口径重算（latest_run.gate 为运行时快照）；放量动作本身待 ENH-03 AI 面装配后消费本判定（接缝已就绪）",
	})
}
