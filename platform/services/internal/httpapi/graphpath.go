// httpapi/graphpath.go — M3-B 攻击路径推演端点（FR-GPH-004，WP-M3-01 重基线）。
// 计算面在 internal/graph（内存 BFS）与 internal/pgstore（递归 CTE）——同一 PathQuery 端口，
// 本文件只做参数校验与直出；未装配=501 graph_path_unavailable（诚实边界，不伪造路径）。
package httpapi

import (
	"net/http"
	"strconv"

	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// handleGraphShortestPath GET /v1/tenants/{id}/graph/paths?from=&to=
func (s *Server) handleGraphShortestPath(w http.ResponseWriter, r *http.Request) {
	if s.paths == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "graph_path_unavailable", "攻击路径推演未装配")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermReadAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无读取权限")
		return
	}
	from, to := r.URL.Query().Get("from"), r.URL.Query().Get("to")
	if from == "" || to == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "bad_request", "from/to 为必填")
		return
	}
	if _, err := s.tenants.Get(r.Context(), p, requestIDOf(r), r.PathValue("id")); err != nil {
		failFrom(w, r, err)
		return
	}
	edges, err := s.paths.ShortestPath(r.Context(), r.PathValue("id"), from, to)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": r.PathValue("id"), "from": from, "to": to, "hops": len(edges),
		"edges": edges, "mitigations": mitigationsOf(edges),
		"reachable": len(edges) > 0,
	})
}

// handleGraphReachable GET /v1/tenants/{id}/graph/reach?from=&to=&depth=
func (s *Server) handleGraphReachable(w http.ResponseWriter, r *http.Request) {
	if s.paths == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "graph_path_unavailable", "攻击路径推演未装配")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermReadAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无读取权限")
		return
	}
	from, to := r.URL.Query().Get("from"), r.URL.Query().Get("to")
	if from == "" || to == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "bad_request", "from/to 为必填")
		return
	}
	depth := graph.DefaultMaxDepth
	if v := r.URL.Query().Get("depth"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= graph.DefaultMaxDepth {
			depth = n
		}
	}
	if _, err := s.tenants.Get(r.Context(), p, requestIDOf(r), r.PathValue("id")); err != nil {
		failFrom(w, r, err)
		return
	}
	ok, edges, err := s.paths.Reachable(r.Context(), r.PathValue("id"), from, to, depth)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": r.PathValue("id"), "from": from, "to": to, "depth": depth,
		"reachable": ok, "edges": edges, "mitigations": mitigationsOf(edges),
	})
}

// handleGraphSubgraph GET /v1/tenants/{id}/graph/subgraph?fp=&depth=
func (s *Server) handleGraphSubgraph(w http.ResponseWriter, r *http.Request) {
	if s.paths == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "graph_path_unavailable", "攻击路径推演未装配")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermReadAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无读取权限")
		return
	}
	fp := r.URL.Query().Get("fp")
	if fp == "" {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "bad_request", "fp 为必填")
		return
	}
	depth := 2
	if v := r.URL.Query().Get("depth"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= graph.DefaultMaxDepth {
			depth = n
		}
	}
	if _, err := s.tenants.Get(r.Context(), p, requestIDOf(r), r.PathValue("id")); err != nil {
		failFrom(w, r, err)
		return
	}
	ents, rels, err := s.paths.Subgraph(r.Context(), r.PathValue("id"), fp, depth)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": r.PathValue("id"), "fp": fp, "depth": depth,
		"entities": ents, "relations": rels,
	})
}

// handleGraphTopPaths GET /v1/tenants/{id}/graph/top-paths?limit=
func (s *Server) handleGraphTopPaths(w http.ResponseWriter, r *http.Request) {
	if s.paths == nil {
		writeError(w, requestIDOf(r), http.StatusNotImplemented, "graph_path_unavailable", "攻击路径推演未装配")
		return
	}
	p := principalOf(r)
	if !p.Can(rbac.PermReadAssets) {
		writeError(w, requestIDOf(r), http.StatusForbidden, "forbidden", "无读取权限")
		return
	}
	limit := graph.DefaultTopN
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 20 {
			limit = n
		}
	}
	if _, err := s.tenants.Get(r.Context(), p, requestIDOf(r), r.PathValue("id")); err != nil {
		failFrom(w, r, err)
		return
	}
	paths, err := s.paths.TopPaths(r.Context(), r.PathValue("id"), limit)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant": r.PathValue("id"), "limit": limit, "paths": paths, "total": len(paths),
		"ranking": "跳数升序→目标种类优先级→起点指纹→终点指纹（确定性，双后端共用）",
	})
}

func mitigationsOf(edges []graph.Relation) []string {
	out := make([]string, 0, len(edges))
	for _, e := range edges {
		out = append(out, graph.Mitigation(e.Type))
	}
	return out
}
