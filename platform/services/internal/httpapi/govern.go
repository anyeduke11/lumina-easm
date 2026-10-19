// IR-05 排查治理端点（判敏 + 风险台账，M1 后端先行块）。
package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/classify"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/notice"
)

// ---- 敏感数据分类（F6 / FR-CLS）----

func (s *Server) handleClassifyRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"catalog": s.cls.Catalog()})
}

func (s *Server) handleClassifyDetect(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Content string         `json:"content"`
		Input   classify.Input `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	hits := s.cls.Detect(in.Content, in.Input)
	if hits == nil {
		hits = []classify.Hit{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": hits, "total": len(hits)})
}

// ---- 风险台账（F4 / FR-LGR）----

type ledgerInView struct {
	ID       string               `json:"id"`
	Phase    string               `json:"phase"`
	Category string               `json:"cat"`
	Asset    string               `json:"asset"`
	Title    string               `json:"title"`
	Level    string               `json:"lv"`
	Source   string               `json:"src"`
	Found    string               `json:"date"`
	Action   string               `json:"action"`
	Owner    string               `json:"owner"`
	Due      string               `json:"due"`
	XChk     []string             `json:"xchk,omitempty"`   // V-5 门1：独立信源（规则/工具/人工复核编号）
	Refute   []ledger.RefuteCheck `json:"refute,omitempty"` // V-10 门2：反证记录（claim/outcome/evidence）
}

func (v ledgerInView) toItem(tenant string) (ledger.Item, error) {
	i := ledger.Item{ID: v.ID, Tenant: tenant, Phase: v.Phase, Category: v.Category,
		Asset: v.Asset, Title: v.Title, Level: v.Level, Source: v.Source,
		Action: v.Action, Owner: v.Owner, XChk: v.XChk, Refute: v.Refute}
	if v.Found != "" {
		t, err := time.Parse(time.RFC3339, v.Found)
		if err != nil {
			return i, err
		}
		i.Found = t
	}
	if v.Due != "" {
		t, err := time.Parse(time.RFC3339, v.Due)
		if err != nil {
			return i, err
		}
		i.Due = t
	}
	return i, nil
}

func (s *Server) handleCreateLedger(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("id")
	var in ledgerInView
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	i, err := in.toItem(tenantID)
	if err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "found/due 必须为 RFC3339")
		return
	}
	if err := s.ledger.Create(r.Context(), principalOf(r), requestIDOf(r), i); err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, i)
}

func (s *Server) handleListLedger(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	items, err := s.ledger.List(r.Context(), principalOf(r), requestIDOf(r), ledger.Filter{
		Status: q.Get("status"), Phase: q.Get("phase"), Cat: q.Get("cat"),
	})
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items), "counts": s.ledger.Counts(r.Context(), principalOf(r))})
}

func (s *Server) handleLedgerAction(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action string `json:"action"` // 状态迁移（FR-LGR-002）；closed 必须走 verify
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Action == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "action 必填（open/doing/notify；closed 请用 verify）")
		return
	}
	if err := s.ledger.SetStatus(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"), in.Action); err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /v1/ledger/{id}/verify —— 复测/验证（S-2 门3）。
// body: {method: sandbox|manual|cross_tool, result: reproduced|refuted|inconclusive, evidence_ref?, note?}
// 语义：reproduced→已闭环（唯一合法路径，且必须带证据引用 C-5）；其余→回退整改中。
// sandbox 未接入 provider=501 verifier_unavailable（不拿「没有沙箱」冒充闭环）。
func (s *Server) handleLedgerVerify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Method      string `json:"method"`
		Result      string `json:"result"`
		EvidenceRef string `json:"evidence_ref"`
		Note        string `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	v := ledger.Verification{
		Method: in.Method, Result: in.Result, EvidenceRef: in.EvidenceRef, Note: in.Note,
	}
	rec, err := s.ledger.Verify(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"), v)
	if err != nil {
		switch {
		case errors.Is(err, ledger.ErrNoVerf):
			// 沙箱 PoC 提供者未接入（ENH-10）：当前禁止以 sandbox 名义闭环——fail loud
			writeError(w, requestIDOf(r), http.StatusNotImplemented, "verifier_unavailable", err.Error())
		case errors.Is(err, ledger.ErrInvalid):
			writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_verification", err.Error())
		default:
			failFrom(w, r, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"method": rec.Method, "result": rec.Result, "verifier": rec.Verifier,
		"evidence_ref": rec.EvidenceRef, "ts": rec.TS,
	})
}

// handleLedgerNotify 台账置「待通报」并发起线索通报（FR-LGR-007 / CR-002 / M2-04）。
// 通报服务装配时：生成**属地公安机关 24h** 单（法定首报目标）落 012——三要素留痕；
// 通报中心 48h 单经 `POST /v1/tenants/{id}/notices` 按需发起（不在此替客户决定双报时点）。
// 未装配时：仅置态并如实返回 notice_persisted=false（不伪造单号=不谎称已生成通报记录）。
func (s *Server) handleLedgerNotify(w http.ResponseWriter, r *http.Request) {
	ctx, p, reqID, id := r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id")
	it, err := s.ledger.Get(ctx, p, reqID, id)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	if err := s.ledger.MarkNotify(ctx, p, reqID, id); err != nil {
		failFrom(w, r, err)
		return
	}
	resp := map[string]any{"ledger": id, "status": "待通报",
		"targets": []string{"属地公安机关(24h)", "省通报中心(48h)"}}
	if s.not == nil {
		resp["notice_id"], resp["notice_persisted"] = "", false
		resp["note"] = "通报服务未装配：仅台账置待通报，未生成 CR-002 通报记录"
		writeJSON(w, http.StatusOK, resp)
		return
	}
	n, err := s.not.Create(ctx, p, reqID, it.Tenant, id, notice.TargetPolice)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	resp["notice_id"], resp["notice_persisted"], resp["notice"] = n.ID, true, n
	writeJSON(w, http.StatusOK, resp)
}
