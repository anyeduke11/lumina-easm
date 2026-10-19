// IR-02 漏洞库/情报库 + 归属判定端点（批三后端 REST 面）。
package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/intel"
	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/vuln"
)

// scopeAssets 主体可见的 租户→资产 集（越权不可见）。
func (s *Server) scopeAssets(r *http.Request) map[string][]asset.Asset {
	out := map[string][]asset.Asset{}
	tenants, err := s.tenants.List(r.Context(), principalOf(r))
	if err != nil {
		return out
	}
	for _, t := range tenants {
		list, _ := s.assets.ListByTenant(r.Context(), principalOf(r), "kb", t.ID)
		out[t.ID] = list
	}
	return out
}

// ---- 漏洞库 ----

func (s *Server) handleListVulns(w http.ResponseWriter, r *http.Request) {
	if s.vuln == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "kb_unavailable", "知识库未启用")
		return
	}
	q := r.URL.Query()
	visible := s.scopeAssets(r) // 影响面以主体可见资产实时重算（可复算=Priority() 唯一入口）
	s.vuln.RecomputePriority(func(e vuln.Entry) int {
		n := 0
		for _, list := range visible {
			n += len(vuln.MatchAssets(e, list))
		}
		return n
	})
	items := s.vuln.List(q.Get("severity"), q.Get("q"))
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func (s *Server) handleImportVulns(w http.ResponseWriter, r *http.Request) {
	if s.vuln == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "kb_unavailable", "知识库未启用")
		return
	}
	if !principalOf(r).Can(rbac.PermWriteAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无写入域权限")
		return
	}
	body, _ := io.ReadAll(r.Body)
	trimmed := strings.TrimSpace(string(body))
	isCSV := strings.EqualFold(r.URL.Query().Get("format"), "csv") || strings.HasPrefix(strings.ToLower(trimmed), "cve,title,")
	var n, sk int
	var err error
	if isCSV {
		n, sk, err = s.vuln.ImportCSV(trimmed)
	} else {
		var items []vuln.Entry
		if err = json.Unmarshal(body, &items); err == nil {
			n, sk, err = s.vuln.ImportJSON(items)
		}
	}
	if err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_import", err.Error())
		return
	}
	if n > 0 && s.mon != nil { // 事件驱动（FR-MON-001/003 近似）：新 CVE 入库即触发匹配扫描
		s.mon.OnImport("vuln", s.scopeAssets(r))
	}
	writeJSON(w, http.StatusOK, map[string]any{"inserted": n, "skipped": sk})
}

func (s *Server) handleVulnDetail(w http.ResponseWriter, r *http.Request) {
	if s.vuln == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "kb_unavailable", "知识库未启用")
		return
	}
	e, ok := s.vuln.Get(r.PathValue("cve"))
	if !ok {
		writeError(w, requestIDOf(r), http.StatusNotFound, "not_found", "CVE 不存在")
		return
	}
	affected := map[string][]asset.Asset{}
	for tid, list := range s.scopeAssets(r) {
		if m := vuln.MatchAssets(e, list); len(m) > 0 {
			affected[tid] = m
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entry": e, "affected_assets": affected})
}

// ---- 情报库 ----

func (s *Server) handleListIntel(w http.ResponseWriter, r *http.Request) {
	if s.intel == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "kb_unavailable", "知识库未启用")
		return
	}
	q := r.URL.Query()
	items := s.intel.List(q.Get("type"), q.Get("family"))
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func (s *Server) handleImportIntel(w http.ResponseWriter, r *http.Request) {
	if s.intel == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "kb_unavailable", "知识库未启用")
		return
	}
	body, _ := io.ReadAll(r.Body)
	trimmed := strings.TrimSpace(string(body))
	isCSV := strings.EqualFold(r.URL.Query().Get("format"), "csv") || strings.HasPrefix(strings.ToLower(trimmed), "type,value,")
	var n, sk int
	var err error
	if isCSV {
		n, sk, err = s.intel.ImportCSV(trimmed)
	} else {
		var items []intel.Entry
		if err = json.Unmarshal(body, &items); err == nil {
			n, sk, err = s.intel.ImportJSON(items)
		}
	}
	if err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_import", err.Error())
		return
	}
	if n > 0 && s.mon != nil { // 新 IOC 入库即触发命中扫描
		s.mon.OnImport("intel", s.scopeAssets(r))
	}
	writeJSON(w, http.StatusOK, map[string]any{"inserted": n, "skipped": sk})
}

func (s *Server) handleIntelHits(w http.ResponseWriter, r *http.Request) {
	if s.intel == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "kb_unavailable", "知识库未启用")
		return
	}
	var all []asset.Asset
	for _, list := range s.scopeAssets(r) {
		all = append(all, list...)
	}
	hits := s.intel.HitAssets(all)
	writeJSON(w, http.StatusOK, map[string]any{"hits": hits, "total": len(hits)})
}

// ---- 归属判定（FR-DSC-010）----

func (s *Server) handleOwnershipJudge(w http.ResponseWriter, r *http.Request) {
	if s.own == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "kb_unavailable", "归属判定未启用")
		return
	}
	var in struct {
		Tenant  string            `json:"tenant_id"`
		Domain  string            `json:"domain"`
		Signals ownership.Signals `json:"signals"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Tenant == "" || in.Domain == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "tenant_id 与 domain 必填")
		return
	}
	p := principalOf(r)
	t, err := s.tenants.Get(r.Context(), p, requestIDOf(r), in.Tenant)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	id := ownership.Identity{Tenant: t.ID, Org: t.Name, Short: t.Short, Domains: t.RootDomains, CIDRs: t.CIDRs}
	v := s.own.Judge(id, in.Domain, in.Signals)
	queued, err := s.own.AdmitOrQueue(r.Context(), t.ID, v, v.Domain) // 非归属态强制复核队列（不入账）
	if err != nil {
		failFrom(w, r, err) // 复核锚点落库失败=上浮（fail loud，不得假装已入队）
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verdict": v, "queued_for_review": queued})
}

func (s *Server) handleOwnershipQueue(w http.ResponseWriter, r *http.Request) {
	if s.own == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "kb_unavailable", "归属判定未启用")
		return
	}
	q := s.own.Queue()
	writeJSON(w, http.StatusOK, map[string]any{"items": q, "total": len(q)})
}

// handleOwnershipResolve 复核队列人工出口（PRD R2：可审计，不静默丢弃；留痕由 Service 追加）。
func (s *Server) handleOwnershipResolve(w http.ResponseWriter, r *http.Request) {
	if s.own == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "kb_unavailable", "归属判定未启用")
		return
	}
	if !principalOf(r).Can(rbac.PermWriteAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无写入域权限")
		return
	}
	seq, err := strconv.Atoi(r.PathValue("seq"))
	if err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "seq 须为数字")
		return
	}
	var in struct {
		Verdict  string `json:"verdict"`
		Reviewer string `json:"reviewer"`
	}
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &in)
	if in.Reviewer == "" || (in.Verdict != ownership.VerdictOwned && in.Verdict != ownership.VerdictSuspect && in.Verdict != ownership.VerdictUnrelated) {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "verdict 须为 归属|疑似|无关 且 reviewer 必填")
		return
	}
	if err := s.own.Resolve(r.Context(), seq, in.Verdict, in.Reviewer); err != nil {
		if errors.Is(err, ownership.ErrQueueNotFound) {
			writeError(w, requestIDOf(r), http.StatusNotFound, "not_found", "队列项不存在")
			return
		}
		failFrom(w, r, err) // 落库失败=复核未生效，fail loud（不得假装已复核）
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"resolved": seq, "verdict": in.Verdict, "reviewer": in.Reviewer})
}

// ---- FR-CHN-005 资产指纹基线（M2-02 首小项：暗网样本归属比对基准）----
// 基线按租户登记，`ownership:judge` 依 tenant_id 自动取用；未登记时携指纹样本判「疑似+基线缺失」
// 进人工复核（不虚判归属、不判无关静默丢弃）。过渡形态=内存，落库随 M2-02 本体。

func (s *Server) handleUpsertFingerprints(w http.ResponseWriter, r *http.Request) {
	if s.own == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "kb_unavailable", "归属判定未启用")
		return
	}
	if !principalOf(r).Can(rbac.PermWriteAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无写入域权限")
		return
	}
	tenantID := r.PathValue("id")
	var fp ownership.Fingerprints
	if err := json.NewDecoder(r.Body).Decode(&fp); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	if _, err := s.tenants.Get(r.Context(), principalOf(r), requestIDOf(r), tenantID); err != nil {
		failFrom(w, r, err) // 租户不存在/越权（跨租户审计 deny 由 tenant 服务落痕）
		return
	}
	if err := s.own.SetFingerprints(r.Context(), tenantID, fp); err != nil {
		failFrom(w, r, err) // 写穿失败=上浮（登记了却没落库的「静默基线」比拒登更危险）
		return
	}
	writeJSON(w, http.StatusCreated, fp)
}

func (s *Server) handleGetFingerprints(w http.ResponseWriter, r *http.Request) {
	if s.own == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "kb_unavailable", "归属判定未启用")
		return
	}
	if !principalOf(r).Can(rbac.PermReadAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无读取域权限")
		return
	}
	tenantID := r.PathValue("id")
	if _, err := s.tenants.Get(r.Context(), principalOf(r), requestIDOf(r), tenantID); err != nil {
		failFrom(w, r, err)
		return
	}
	fp, ok := s.own.FingerprintsOf(tenantID)
	if !ok {
		writeError(w, requestIDOf(r), http.StatusNotFound, "not_found", "该租户未登记指纹基线")
		return
	}
	writeJSON(w, http.StatusOK, fp)
}
