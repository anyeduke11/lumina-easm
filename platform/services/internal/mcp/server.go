// Package mcp 实现 MCP Server 骨架（WP-M0-08 / IR-08 / FR-AGT-004）。
// MVP 暴露三个只读工具；高危分级与防腐层审批（设计方案 §8.2/§8.3、ENH-10 前置）在 M2 叠加。
// 鉴权复用 httpapi 同一令牌主体，Scope 过滤在工具层强制执行——Harness 无特权路径（AX-5）。
package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/classify"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/sweep"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

const protocolVersion = "2024-11-05"

type Server struct {
	tenants *tenant.Service
	assets  *asset.Service
	cls     *classify.Engine
	led     *ledger.Service
	sweeps  *sweep.Service // ENH-01：Temporal 异步化后 Agent 的进度查询面（IR-08）
	tokens  map[string]rbac.Principal
}

type Option func(*Server)

func WithLedger(l *ledger.Service) Option { return func(s *Server) { s.led = l } }
func WithSweep(sv *sweep.Service) Option  { return func(s *Server) { s.sweeps = sv } }

func New(t *tenant.Service, a *asset.Service, tokens map[string]rbac.Principal, opts ...Option) *Server {
	s := &Server{tenants: t, assets: a, cls: classify.New(), tokens: tokens}
	for _, o := range opts {
		o(s)
	}
	return s
}

// ---- JSON-RPC 2.0 ----

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResp struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

func errObj(id any, code int, msg string) rpcResp {
	return rpcResp{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

type toolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func (s *Server) toolDefs() []toolDef {
	t := []toolDef{
		{Name: "list_tenants", Description: "列出主体有权访问的租户", InputSchema: map[string]any{"type": "object", "properties": map[string]any{}}},
		{Name: "search_assets", Description: "在授权租户内按关键词/风险/类型检索资产", InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tenant_id": map[string]any{"type": "string"},
				"q":         map[string]any{"type": "string"},
				"risk":      map[string]any{"type": "string"},
				"type":      map[string]any{"type": "string"},
			},
		}},
		{Name: "get_asset", Description: "按 id 读取资产画像（越权拒绝）", InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"asset_id": map[string]any{"type": "string"}},
			"required":   []string{"asset_id"},
		}},
		{Name: "detect_sensitive_data", Description: "对内容执行三类 22 规则敏感数据识别（FR-CLS/FR-AGT-004）", InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"content": map[string]any{"type": "string"},
				"input":   map[string]any{"type": "object", "description": "结构化通道 {url,ports[],tech[],title}"},
			},
			"required": []string{"content"},
		}},
	}
	if s.led != nil {
		t = append(t, toolDef{Name: "list_ledger", Description: "查询风险台账（可按状态/阶段筛选）", InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tenant_id": map[string]any{"type": "string"},
				"status":    map[string]any{"type": "string"},
				"phase":     map[string]any{"type": "string"},
			},
		}})
	}
	if s.sweeps != nil {
		t = append(t, toolDef{Name: "get_sweep_status", Description: "按 sweep id 查询排查任务进度（Temporal 异步派发后的轮询面）", InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"sweep_id": map[string]any{"type": "string"}},
			"required":   []string{"sweep_id"},
		}})
	}
	return t
}

// Handler 返回 MCP over HTTP(SSE 之外的 Streamable-HTTP 简化形态) 处理器。
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method must be POST", http.StatusMethodNotAllowed)
			return
		}
		var req rpcReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, errObj(nil, -32700, "parse error"))
			return
		}
		p, ok := s.tokens[bearer(r)]
		if !ok {
			writeJSON(w, errObj(req.ID, -32001, "unauthenticated"))
			return
		}
		switch req.Method {
		case "initialize":
			writeJSON(w, rpcResp{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
				"protocolVersion": protocolVersion,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "easm-mcp", "version": "0.1.0"},
			}})
		case "tools/list":
			writeJSON(w, rpcResp{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": s.toolDefs()}})
		case "tools/call":
			s.callTool(w, r.Context(), req, p)
		default:
			writeJSON(w, errObj(req.ID, -32601, "method not found: "+req.Method))
		}
	})
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// toolResult 为 MCP content[] 结构。
func toolResult(id any, v any) rpcResp {
	b, _ := json.Marshal(v)
	return rpcResp{JSONRPC: "2.0", ID: id, Result: map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(b)}},
		"isError": false,
	}}
}

func (s *Server) callTool(w http.ResponseWriter, ctx context.Context, req rpcReq, p rbac.Principal) {
	var cp callParams
	if err := json.Unmarshal(req.Params, &cp); err != nil {
		writeJSON(w, errObj(req.ID, -32602, "invalid params"))
		return
	}
	var args map[string]any
	_ = json.Unmarshal(cp.Arguments, &args)

	switch cp.Name {
	case "list_tenants":
		list, err := s.tenants.List(ctx, p)
		if err != nil {
			writeJSON(w, toolError(req.ID, err.Error()))
			return
		}
		writeJSON(w, toolResult(req.ID, list))
	case "search_assets":
		out, err := s.searchAssets(ctx, p, args)
		if err != nil {
			writeJSON(w, toolError(req.ID, err.Error()))
			return
		}
		writeJSON(w, toolResult(req.ID, out))
	case "get_asset":
		id, _ := args["asset_id"].(string)
		if id == "" {
			writeJSON(w, toolError(req.ID, "asset_id required"))
			return
		}
		a, err := s.assets.GetByID(ctx, p, "mcp", id)
		if err != nil {
			writeJSON(w, toolError(req.ID, err.Error()))
			return
		}
		writeJSON(w, toolResult(req.ID, a))
	case "detect_sensitive_data":
		content, _ := args["content"].(string)
		var in classify.Input
		if raw, ok := args["input"]; ok {
			b, _ := json.Marshal(raw)
			_ = json.Unmarshal(b, &in)
		}
		hits := s.cls.Detect(content, in)
		if hits == nil {
			hits = []classify.Hit{}
		}
		writeJSON(w, toolResult(req.ID, hits))
	case "list_ledger":
		if s.led == nil {
			writeJSON(w, toolError(req.ID, "ledger not enabled"))
			return
		}
		tid, _ := args["tenant_id"].(string)
		st, _ := args["status"].(string)
		ph, _ := args["phase"].(string)
		if tid != "" && !p.InScope(tid) {
			writeJSON(w, toolError(req.ID, rbac.ErrCrossTenant.Error()))
			return
		}
		items, err := s.led.List(ctx, p, "mcp", ledger.Filter{Tenant: tid, Status: st, Phase: ph})
		if err != nil {
			writeJSON(w, toolError(req.ID, err.Error()))
			return
		}
		writeJSON(w, toolResult(req.ID, items))
	case "get_sweep_status":
		if s.sweeps == nil {
			writeJSON(w, toolError(req.ID, "sweep not enabled"))
			return
		}
		id, _ := args["sweep_id"].(string)
		sw, ok := s.sweeps.Get(id)
		// 未知 id 与越权统一口径拒绝——不泄露行存在性（与 get_asset 的 403/404 合并语义一致）
		if !ok || !p.InScope(sw.Tenant) {
			writeJSON(w, toolError(req.ID, "sweep not found: "+id))
			return
		}
		writeJSON(w, toolResult(req.ID, map[string]any{
			"id": sw.ID, "tenant": sw.Tenant, "status": sw.Status,
			"phases": sw.Phases, "steps": len(sw.Steps), "findings": sw.Findings,
			"error": sw.Error, "started_at": sw.StartedAt, "ended_at": sw.EndedAt,
		}))
	default:
		writeJSON(w, errObj(req.ID, -32602, "unknown tool: "+cp.Name))
	}
}

// searchAssets 按主体 Scope 限定租户，再过滤；绝不跨权（AX-5）。
func (s *Server) searchAssets(ctx context.Context, p rbac.Principal, args map[string]any) ([]asset.Asset, error) {
	q, _ := args["q"].(string)
	risk, _ := args["risk"].(string)
	typ, _ := args["type"].(string)

	// 候选租户：显式指定须在 Scope 内；否则用主体可见租户集合
	if tid, _ := args["tenant_id"].(string); tid != "" {
		if !p.InScope(tid) {
			return nil, rbac.ErrCrossTenant
		}
		return filterAssets(listOne(ctx, s, p, tid), q, risk, typ), nil
	}
	tenantsList, err := s.tenants.List(ctx, p)
	if err != nil {
		return nil, err
	}
	var all []asset.Asset
	for _, t := range tenantsList {
		all = append(all, filterAssets(listOne(ctx, s, p, t.ID), q, risk, typ)...)
	}
	return all, nil
}

func listOne(ctx context.Context, s *Server, p rbac.Principal, tid string) []asset.Asset {
	list, _ := s.assets.ListByTenant(ctx, p, "mcp", tid)
	return list
}

func filterAssets(in []asset.Asset, q, risk, typ string) []asset.Asset {
	out := make([]asset.Asset, 0, len(in))
	for _, a := range in {
		if risk != "" && a.Risk != risk {
			continue
		}
		if typ != "" && a.Type != typ {
			continue
		}
		if q != "" && !containsFold(a.Name, q) && !containsFold(a.IP, q) {
			continue
		}
		out = append(out, a)
	}
	return out
}

func containsFold(hay, needle string) bool {
	if needle == "" {
		return true
	}
	return strings.Contains(strings.ToLower(hay), strings.ToLower(needle))
}

func toolError(id any, msg string) rpcResp {
	return rpcResp{JSONRPC: "2.0", ID: id, Result: map[string]any{
		"content": []map[string]any{{"type": "text", "text": msg}},
		"isError": true,
	}}
}

func bearer(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && h[:len(prefix)] == prefix {
		return h[len(prefix):]
	}
	return ""
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
