// IR-06 图谱端点（MVP 一跳邻接子集；多跳/最短路径为增强项 ENH-02，见开发计划 §14.2）。
package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/ingest"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

type entityView struct {
	Kind        string            `json:"kind"`
	Fingerprint string            `json:"fingerprint"`
	Props       map[string]string `json:"props,omitempty"`
	FirstSeen   string            `json:"first_seen"`
	LastSeen    string            `json:"last_seen"`
	InScope     bool              `json:"in_scope"`
	Sources     []string          `json:"sources,omitempty"`
}

type relationView struct {
	Type     string `json:"type"`
	From     string `json:"from"`
	To       string `json:"to"`
	Ts       string `json:"ts"`
	Evidence string `json:"evidence,omitempty"`
}

func toEntityView(e graph.Entity) entityView {
	return entityView{
		Kind: e.Kind, Fingerprint: e.Fingerprint, Props: e.Props,
		FirstSeen: e.FirstSeen.UTC().Format(time.RFC3339),
		LastSeen:  e.LastSeen.UTC().Format(time.RFC3339),
		InScope:   e.InScope, Sources: e.Sources,
	}
}

func toRelationViews(rs []graph.Relation) []relationView {
	out := make([]relationView, 0, len(rs))
	for _, r := range rs {
		out = append(out, relationView{
			Type: r.Type, From: r.FromFP, To: r.ToFP, Evidence: r.EvidenceRef,
			Ts: r.TS.UTC().Format(time.RFC3339),
		})
	}
	return out
}

// handleGraphEntity：按资产 id 查其图谱实体与一跳邻居（先经资产鉴权，越权 403）。
func (s *Server) handleGraphEntity(w http.ResponseWriter, r *http.Request) {
	if s.graph == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "graph_unavailable", "图谱读取未启用")
		return
	}
	a, err := s.assets.GetByID(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	fp := ingest.FingerprintForAsset(a)
	if fp == "" {
		writeError(w, requestIDOf(r), http.StatusNotFound, "not_projected", "该资产类型未投影到图谱（增强项 M1）")
		return
	}
	e, found, err := s.graph.EntityByFingerprint(r.Context(), a.Tenant, fp)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	if !found {
		writeError(w, requestIDOf(r), http.StatusNotFound, "not_found", "图谱实体不存在")
		return
	}
	nb, _ := s.graph.Neighbors(r.Context(), a.Tenant, fp)
	writeJSON(w, http.StatusOK, map[string]any{"entity": toEntityView(e), "neighbors": toRelationViews(nb)})
}

// handleGraphQuery：按 (tenant, fingerprint) 查一跳邻接；先校验主体 Scope（FR-TEN-005）。
func (s *Server) handleGraphQuery(w http.ResponseWriter, r *http.Request) {
	if s.graph == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "graph_unavailable", "图谱读取未启用")
		return
	}
	var in struct {
		Tenant      string `json:"tenant"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	p := principalOf(r)
	if !p.InScope(in.Tenant) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "cross_tenant_denied", rbac.ErrCrossTenant.Error())
		return
	}
	nb, err := s.graph.Neighbors(r.Context(), in.Tenant, in.Fingerprint)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"neighbors": toRelationViews(nb), "total": len(nb)})
}
