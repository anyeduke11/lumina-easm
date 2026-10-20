// Package mcp 实现 MCP Server 骨架（WP-M0-08 / IR-08 / FR-AGT-004；M4-04 全量开放 WP-M4-04）。
// 工具分级=C-4 唯一权限口径（设计方案 §8.2）：readonly/controlled/dangerous，
// 每个工具携带 level 字段；受控动作审计留痕，高危动作与 REST 同闸不特权（AX-5/§8.3）。
// 鉴权复用 httpapi 同一令牌主体，Scope 过滤在工具层强制执行——Harness 无特权路径（AX-5）。
// 全部调用（allow/deny）写 audit 日志（授权审计完整，WP-M4-04 验收）。
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/authn"
	"github.com/wangdev88/easm-platform/platform/services/internal/classify"
	"github.com/wangdev88/easm-platform/platform/services/internal/collect"
	"github.com/wangdev88/easm-platform/platform/services/internal/confirm"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/intel"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
	"github.com/wangdev88/easm-platform/platform/services/internal/notice"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/report"
	"github.com/wangdev88/easm-platform/platform/services/internal/sweep"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
	"github.com/wangdev88/easm-platform/platform/services/internal/vuln"
	"github.com/wangdev88/easm-platform/platform/services/internal/workorder"
)

const protocolVersion = "2024-11-05"

// C-4 工具分级（设计方案 §8.2 唯一口径）：只读自动放行、受控记录审计、高危强制授权闸。
const (
	LevelReadonly   = "readonly"
	LevelControlled = "controlled"
	LevelDangerous  = "dangerous"
)

type Server struct {
	tenants    *tenant.Service
	assets     *asset.Service
	cls        *classify.Engine
	led        *ledger.Service
	sweeps     *sweep.Service   // ENH-01：Temporal 异步化后 Agent 的进度查询面（IR-08）
	mon        *monitor.Service // M4-04：告警查询面
	wo         *workorder.Service
	nn         *notice.Service
	rpt        *report.Service
	paths      graph.PathQuery // nil=graph 工具如实报未装配（与 REST 501 同语义）
	vulns      *vuln.Service
	intels     *intel.Service
	col        *collect.Service // nil=scan_active 如实报未装配
	confirm    *confirm.Service // AX-5：高危动作一次性确认（与 REST 同闸）
	confirmReq bool             // EASM_REQUIRE_CONFIRMATION 开启时强制携带
	al         audit.Log        // M4-04：allow/deny 全量审计（nil=不审计，仅测试装配）
	tokens     map[string]rbac.Principal
	oidc       *authn.OIDC
	breakglass *authn.BreakGlass
}

type Option func(*Server)

func WithLedger(l *ledger.Service) Option { return func(s *Server) { s.led = l } }
func WithSweep(sv *sweep.Service) Option  { return func(s *Server) { s.sweeps = sv } }
func WithMonitor(m *monitor.Service) Option {
	return func(s *Server) { s.mon = m }
}
func WithWorkOrders(w *workorder.Service) Option { return func(s *Server) { s.wo = w } }
func WithNotices(n *notice.Service) Option       { return func(s *Server) { s.nn = n } }
func WithReport(r *report.Service) Option        { return func(s *Server) { s.rpt = r } }
func WithPaths(pq graph.PathQuery) Option        { return func(s *Server) { s.paths = pq } }
func WithVulnIntel(v *vuln.Service, i *intel.Service) Option {
	return func(s *Server) { s.vulns, s.intels = v, i }
}
func WithCollect(c *collect.Service) Option { return func(s *Server) { s.col = c } }
func WithConfirmation(c *confirm.Service, required bool) Option {
	return func(s *Server) { s.confirm, s.confirmReq = c, required }
}
func WithAudit(l audit.Log) Option              { return func(s *Server) { s.al = l } }
func WithOIDC(o *authn.OIDC) Option             { return func(s *Server) { s.oidc = o } }
func WithBreakGlass(b *authn.BreakGlass) Option { return func(s *Server) { s.breakglass = b } }

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
	Level       string         `json:"level"` // C-4 分级：readonly/controlled/dangerous
	InputSchema map[string]any `json:"inputSchema"`
}

func (s *Server) toolDefs() []toolDef {
	t := []toolDef{
		{Name: "list_tenants", Level: LevelReadonly, Description: "列出主体有权访问的租户", InputSchema: map[string]any{"type": "object", "properties": map[string]any{}}},
		{Name: "search_assets", Level: LevelReadonly, Description: "在授权租户内按关键词/风险/类型检索资产", InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tenant_id": map[string]any{"type": "string"},
				"q":         map[string]any{"type": "string"},
				"risk":      map[string]any{"type": "string"},
				"type":      map[string]any{"type": "string"},
			},
		}},
		{Name: "get_asset", Level: LevelReadonly, Description: "按 id 读取资产画像（越权拒绝）", InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"asset_id": map[string]any{"type": "string"}},
			"required":   []string{"asset_id"},
		}},
		{Name: "detect_sensitive_data", Level: LevelReadonly, Description: "对内容执行三类 22 规则敏感数据识别（FR-CLS/FR-AGT-004）", InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"content": map[string]any{"type": "string"},
				"input":   map[string]any{"type": "object", "description": "结构化通道 {url,ports[],tech[],title}"},
			},
			"required": []string{"content"},
		}},
	}
	if s.led != nil {
		t = append(t, toolDef{Name: "list_ledger", Level: LevelReadonly, Description: "查询风险台账（可按状态/阶段筛选）", InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tenant_id": map[string]any{"type": "string"},
				"status":    map[string]any{"type": "string"},
				"phase":     map[string]any{"type": "string"},
			},
		}})
	}
	if s.sweeps != nil {
		t = append(t, toolDef{Name: "get_sweep_status", Level: LevelReadonly, Description: "按 sweep id 查询排查任务进度（Temporal 异步派发后的轮询面）", InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"sweep_id": map[string]any{"type": "string"}},
			"required":   []string{"sweep_id"},
		}})
	}
	// ---- M4-04 全量开放（WP-M4-04；设计方案 §8.2 分级）----
	if s.mon != nil {
		t = append(t, toolDef{Name: "list_alerts", Level: LevelReadonly, Description: "查询告警（可按 kind 过滤；输出按主体 Scope 租户过滤）", InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"kind": map[string]any{"type": "string", "description": "vuln_match|intel_hit"}},
		}})
	}
	if s.wo != nil {
		t = append(t, toolDef{Name: "list_workorders", Level: LevelReadonly, Description: "查询处置工单（五态跟踪）", InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tenant_id": map[string]any{"type": "string"},
				"status":    map[string]any{"type": "string"},
			},
			"required": []string{"tenant_id"},
		}})
	}
	if s.nn != nil {
		t = append(t, toolDef{Name: "list_notices", Level: LevelReadonly, Description: "查询线索通报（公安 24h/通报中心 48h 口径）", InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tenant_id": map[string]any{"type": "string"},
				"status":    map[string]any{"type": "string"},
			},
			"required": []string{"tenant_id"},
		}})
	}
	if s.rpt != nil {
		t = append(t, toolDef{Name: "list_reports", Level: LevelReadonly, Description: "查询已生成报告历史", InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"tenant_id": map[string]any{"type": "string"}},
			"required":   []string{"tenant_id"},
		}})
	}
	if s.paths != nil {
		t = append(t, toolDef{Name: "graph_top_paths", Level: LevelReadonly, Description: "查询租户 TopN 攻击路径（M3-B 图谱推演）", InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tenant_id": map[string]any{"type": "string"},
				"limit":     map[string]any{"type": "integer", "description": "默认 5"},
			},
			"required": []string{"tenant_id"},
		}})
	}
	if s.vulns != nil {
		t = append(t, toolDef{Name: "list_vulns", Level: LevelReadonly, Description: "查询漏洞知识库（可按严重级/关键词过滤）", InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"severity": map[string]any{"type": "string"},
				"q":        map[string]any{"type": "string"},
			},
		}})
	}
	if s.vulns != nil || s.intels != nil {
		t = append(t, toolDef{Name: "knowledge_export", Level: LevelReadonly, Description: "导出知识库条目（漏洞+情报；ENH-02 向量库未装=如实标注不冒充已向量化）", InputSchema: map[string]any{
			"type": "object", "properties": map[string]any{},
		}})
	}
	if s.sweeps != nil {
		t = append(t, toolDef{Name: "scan_schedule", Level: LevelControlled, Description: "对授权租户触发一次排查（P1–P5；与 REST /v1/sweeps 同一授权闸与 Scope 校验）", InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tenant_id": map[string]any{"type": "string"},
				"phases":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "空=全阶段"},
			},
			"required": []string{"tenant_id"},
		}})
	}
	if s.rpt != nil {
		t = append(t, toolDef{Name: "report_generate", Level: LevelControlled, Description: "生成报告初稿（人审后发布；内容哈希可复算）", InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tenant_id": map[string]any{"type": "string"},
				"period":    map[string]any{"type": "string"},
				"audience":  map[string]any{"type": "string"},
				"sections":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			},
			"required": []string{"tenant_id"},
		}})
	}
	if s.col != nil {
		t = append(t, toolDef{Name: "scan_active", Level: LevelDangerous, Description: "主动扫描（端口/目录；须有效授权单，授权闸/时间窗/限速与 REST 完全同闸，AX-5 高危；确认闸开启时须携带 confirmation_id）", InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tenant_id":       map[string]any{"type": "string"},
				"mode":            map[string]any{"type": "string", "enum": []string{"port", "dir"}},
				"target":          map[string]any{"type": "string"},
				"ports":           map[string]any{"type": "string", "description": "mode=port 必填，如 80,443"},
				"confirmation_id": map[string]any{"type": "string", "description": "高危动作一次性确认（POST /v1/confirmations 创建；也可用 X-EASM-Confirmation 头）"},
			},
			"required": []string{"tenant_id", "mode", "target"},
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
		tok := bearer(r)
		p, ok := s.tokens[tok]
		if !ok && s.oidc != nil {
			if pp, err := s.oidc.Verify(r.Context(), tok); err == nil {
				p, ok = pp, true
			}
		}
		if !ok && s.breakglass != nil && s.breakglass.Verify(tok) {
			p = rbac.Principal{UserID: "breakglass", Role: "admin", TenantIDs: []string{"*"}}
			ok = true
			s.breakglass.Use(r.Context(), "")
		}
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
			s.callTool(w, r, req, p)
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

func (s *Server) callTool(w http.ResponseWriter, r *http.Request, req rpcReq, p rbac.Principal) {
	ctx := r.Context()
	var cp callParams
	if err := json.Unmarshal(req.Params, &cp); err != nil {
		writeJSON(w, errObj(req.ID, -32602, "invalid params"))
		return
	}
	var args map[string]any
	_ = json.Unmarshal(cp.Arguments, &args)

	// M4-04 授权审计完整：每个工具调用（allow/deny）全量落 audit（WP-M4-04 验收；
	// AX-5 人在环可审计——AI/Harness 发起与人工发起同留痕，无特权路径）。
	denied := false
	denyAudit := func(tid, reason string) {
		denied = true
		s.audit(ctx, p, cp.Name, tid, audit.ResultDeny, reason)
	}
	defer func() {
		if !denied {
			tid, _ := args["tenant_id"].(string)
			s.audit(ctx, p, cp.Name, tid, audit.ResultAllow, "")
		}
	}()

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
			denyAudit(tid, rbac.ErrCrossTenant.Error())
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
			denyAudit(sw.Tenant, "sweep not found: "+id)
			writeJSON(w, toolError(req.ID, "sweep not found: "+id))
			return
		}
		writeJSON(w, toolResult(req.ID, map[string]any{
			"id": sw.ID, "tenant": sw.Tenant, "status": sw.Status,
			"phases": sw.Phases, "steps": len(sw.Steps), "findings": sw.Findings,
			"error": sw.Error, "started_at": sw.StartedAt, "ended_at": sw.EndedAt,
		}))
	case "list_alerts":
		if s.mon == nil {
			writeJSON(w, toolError(req.ID, "monitor not enabled"))
			return
		}
		kind, _ := args["kind"].(string)
		var out []monitor.Alert
		for _, a := range s.mon.List(kind) { // Scope 过滤在工具层强制（AX-5：MCP 无特权）
			if p.InScope(a.TenantID) {
				out = append(out, a)
			}
		}
		if out == nil {
			out = []monitor.Alert{}
		}
		writeJSON(w, toolResult(req.ID, out))
	case "list_workorders":
		s.tenantScopedCall(w, req, ctx, p, cp.Name, args, func(tid string) (any, error) {
			if s.wo == nil {
				return nil, errNotEnabled("workorder")
			}
			st, _ := args["status"].(string)
			return s.wo.List(ctx, p, "mcp", tid, st)
		})
	case "list_notices":
		s.tenantScopedCall(w, req, ctx, p, cp.Name, args, func(tid string) (any, error) {
			if s.nn == nil {
				return nil, errNotEnabled("notice")
			}
			st, _ := args["status"].(string)
			return s.nn.List(ctx, p, "mcp", tid, st)
		})
	case "list_reports":
		s.tenantScopedCall(w, req, ctx, p, cp.Name, args, func(tid string) (any, error) {
			if s.rpt == nil {
				return nil, errNotEnabled("report")
			}
			return s.rpt.List(ctx, p, "mcp", tid)
		})
	case "graph_top_paths":
		s.tenantScopedCall(w, req, ctx, p, cp.Name, args, func(tid string) (any, error) {
			if s.paths == nil {
				return nil, errNotEnabled("graph")
			}
			limit := 5
			if v, ok := args["limit"].(float64); ok && int(v) > 0 && int(v) <= 50 {
				limit = int(v)
			}
			return s.paths.TopPaths(ctx, tid, limit)
		})
	case "list_vulns":
		if s.vulns == nil {
			writeJSON(w, toolError(req.ID, "vuln not enabled"))
			return
		}
		sev, _ := args["severity"].(string)
		q, _ := args["q"].(string)
		writeJSON(w, toolResult(req.ID, s.vulns.List(sev, q)))
	case "knowledge_export":
		writeJSON(w, toolResult(req.ID, s.knowledgeExport()))
	case "scan_schedule":
		if s.sweeps == nil {
			writeJSON(w, toolError(req.ID, "sweep not enabled"))
			return
		}
		if !p.Can(rbac.PermWriteAssets) { // 受控级：与 REST 同权限（§8.2 记录审计）
			tid, _ := args["tenant_id"].(string)
			denyAudit(tid, "requires write_assets permission")
			writeJSON(w, toolError(req.ID, "requires write_assets permission"))
			return
		}
		s.tenantScopedCall(w, req, ctx, p, cp.Name, args, func(tid string) (any, error) {
			var phases []string
			if raw, ok := args["phases"].([]any); ok {
				for _, v := range raw {
					if sv, ok := v.(string); ok {
						phases = append(phases, sv)
					}
				}
			}
			return s.sweeps.Execute(ctx, p, "mcp", tid, phases) // 同一授权闸（SetScope）不特权
		})
	case "report_generate":
		if s.rpt == nil {
			writeJSON(w, toolError(req.ID, "report not enabled"))
			return
		}
		if !p.Can(rbac.PermWriteAssets) {
			tid, _ := args["tenant_id"].(string)
			denyAudit(tid, "requires write_assets permission")
			writeJSON(w, toolError(req.ID, "requires write_assets permission"))
			return
		}
		s.tenantScopedCall(w, req, ctx, p, cp.Name, args, func(tid string) (any, error) {
			in := report.Params{Tenant: tid}
			in.Period, _ = args["period"].(string)
			in.Audience, _ = args["audience"].(string)
			if raw, ok := args["sections"].([]any); ok {
				for _, v := range raw {
					if sv, ok := v.(string); ok {
						in.Sections = append(in.Sections, sv)
					}
				}
			}
			return s.rpt.Generate(ctx, p, "mcp", in)
		})
	case "scan_active":
		tid, _ := args["tenant_id"].(string)
		mode, _ := args["mode"].(string)
		target, _ := args["target"].(string)
		// 高危（AX-5）：与 REST 同闸——PermWriteAssets+Scope 在此校验，
		// 授权单有效性/时间窗/排除项/限速由 collect.Service 内部 authz.Validate 强制。
		if s.col == nil {
			writeJSON(w, toolError(req.ID, "collect not enabled"))
			return
		}
		if tid == "" || target == "" || (mode != "port" && mode != "dir") {
			denyAudit(tid, "tenant_id/mode(port|dir)/target 必填")
			writeJSON(w, toolError(req.ID, "tenant_id/mode(port|dir)/target 必填"))
			return
		}
		if !p.Can(rbac.PermWriteAssets) {
			denyAudit(tid, "requires write_assets permission")
			writeJSON(w, toolError(req.ID, "requires write_assets permission"))
			return
		}
		if !p.InScope(tid) {
			denyAudit(tid, rbac.ErrCrossTenant.Error())
			writeJSON(w, toolError(req.ID, rbac.ErrCrossTenant.Error()))
			return
		}
		// AX-5 同闸：确认闸开启时，MCP 高危动作与 REST 一样必须携带一次性确认
		// （confirmation_id 参数优先，其次 X-EASM-Confirmation 头）——无特权路径。
		if s.confirmReq {
			if s.confirm == nil {
				denyAudit(tid, "confirmation unavailable")
				writeJSON(w, toolError(req.ID, "confirmation unavailable"))
				return
			}
			cid, _ := args["confirmation_id"].(string)
			if cid == "" {
				cid = r.Header.Get("X-EASM-Confirmation")
			}
			if cid == "" {
				denyAudit(tid, "confirmation required")
				writeJSON(w, toolError(req.ID, "confirmation required: 先 POST /v1/confirmations 创建，再以 confirmation_id 参数携带"))
				return
			}
			action := "scan." + mode
			if err := s.confirm.Consume(ctx, p, "mcp", cid, tid, action); err != nil {
				denyAudit(tid, err.Error())
				writeJSON(w, toolError(req.ID, err.Error()))
				return
			}
		}
		var (
			res collect.Result
			err error
		)
		if mode == "port" {
			ports, _ := args["ports"].(string)
			if ports == "" {
				denyAudit(tid, "mode=port 须提供 ports")
				writeJSON(w, toolError(req.ID, "mode=port 须提供 ports"))
				return
			}
			res, err = s.col.ScanPort(ctx, p, "mcp", tid, target, ports, "mcp")
		} else {
			res, err = s.col.ScanDir(ctx, p, "mcp", tid, target, "mcp")
		}
		if err != nil {
			denyAudit(tid, err.Error()) // 授权闸拒绝（如授权单过期）=deny 审计
			writeJSON(w, toolError(req.ID, err.Error()))
			return
		}
		writeJSON(w, toolResult(req.ID, res))
	default:
		writeJSON(w, errObj(req.ID, -32602, "unknown tool: "+cp.Name))
	}
}

// audit 写 allow/deny 审计（nil=未装配不写，仅测试面）。
func (s *Server) audit(ctx context.Context, p rbac.Principal, tool, tid, result, reason string) {
	if s.al == nil {
		return
	}
	_ = s.al.Append(ctx, audit.Entry{
		TS: time.Now().UTC(), Actor: p.UserID, Action: "mcp." + tool, TenantID: tid,
		Resource: tool, Result: result, RequestID: reason,
	})
}

// tenantScopedCall 统一形态：tenant_id 必填 + Scope 校验 + deny 审计 + 委托取数。
func (s *Server) tenantScopedCall(w http.ResponseWriter, req rpcReq, ctx context.Context,
	p rbac.Principal, tool string, args map[string]any, fn func(tid string) (any, error)) {
	tid, _ := args["tenant_id"].(string)
	if tid == "" {
		writeJSON(w, toolError(req.ID, "tenant_id required"))
		return
	}
	if !p.InScope(tid) {
		s.audit(ctx, p, tool, tid, audit.ResultDeny, rbac.ErrCrossTenant.Error())
		writeJSON(w, toolError(req.ID, rbac.ErrCrossTenant.Error()))
		return
	}
	out, err := fn(tid)
	if err != nil {
		writeJSON(w, toolError(req.ID, err.Error()))
		return
	}
	writeJSON(w, toolResult(req.ID, out))
}

func errNotEnabled(domain string) error {
	return fmt.Errorf("%s not enabled", domain)
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
