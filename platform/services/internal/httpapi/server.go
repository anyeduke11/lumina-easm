// Package httpapi 暴露 REST 出口骨架（IR-01 / SRS 统一约定：JSON、ISO8601、
// 错误体 {error:{code,message,request_id}}、分页 page/page_size 上限 500）。
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/authz"
	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
	"github.com/wangdev88/easm-platform/platform/services/internal/classify"
	"github.com/wangdev88/easm-platform/platform/services/internal/collect"
	"github.com/wangdev88/easm-platform/platform/services/internal/darkweb"
	"github.com/wangdev88/easm-platform/platform/services/internal/evalset"
	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/intel"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
	"github.com/wangdev88/easm-platform/platform/services/internal/notice"
	"github.com/wangdev88/easm-platform/platform/services/internal/notify"
	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
	"github.com/wangdev88/easm-platform/platform/services/internal/plugin"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/report"
	"github.com/wangdev88/easm-platform/platform/services/internal/scoring"
	"github.com/wangdev88/easm-platform/platform/services/internal/secret"
	"github.com/wangdev88/easm-platform/platform/services/internal/shadowit"
	"github.com/wangdev88/easm-platform/platform/services/internal/sweep"
	"github.com/wangdev88/easm-platform/platform/services/internal/syntax"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
	"github.com/wangdev88/easm-platform/platform/services/internal/vuln"
	"github.com/wangdev88/easm-platform/platform/services/internal/workorder"
)

type ctxKey int

const (
	keyPrincipal ctxKey = iota
	keyRequestID
)

type Server struct {
	tenants  *tenant.Service
	assets   *asset.Service
	tokens   map[string]rbac.Principal
	graph    GraphQuery         // 可选：IR-06 图谱读取；nil 时图谱端点返回 501
	cls      *classify.Engine   // F6 判敏（无外部依赖，默认注入）
	ledger   *ledger.Service    // F4 风险台账
	sweeps   *sweep.Service     // F2 五阶段工作流
	authz    *authz.Service     // 授权范围（CR-005 / 一票否决⑥）
	plugins  *plugin.Registry   // 工具插件注册中心（FR-PLG）
	vuln     *vuln.Service      // F9.1 漏洞库
	intel    *intel.Service     // F9.3 情报库
	own      *ownership.Service // FR-DSC-010 归属判定
	mon      *monitor.Service   // F14 监测与预警（近似版）
	notify   *notify.Service    // F14.4 告警统一出口
	evid     evidence.Store     // ENH-05 证据对象存储（file|minio）；nil=端点 501
	cands    *candidate.Service // WP-M1-05 候选契约（M2 前置）
	col      *collect.Service   // M2-01 采集管道（repo.secret 首渠道）
	dark     *darkweb.Service   // M2-02 暗网兜底/线索包（FR-CHN-005~008）
	wos      *workorder.Service // M2-03 平台处置工单（FR-CHN-004 五态跟踪）
	not      *notice.Service    // M2-04 线索通报与合规报送（FR-LGR-007/008、CR-002、A-08）
	rpt      *report.Service    // M2-09 报告中心（FR-RPT-001~004：实时聚合/四受众/历史/md-json）
	dispatch SweepDispatcher    // ENH-01：非 nil 时 sweep 走 Temporal 异步派发
	scoreW   scoring.Weights    // M3-A 四因子权重（默认=登记口径，G8-01 待定稿）
	scoreTh  scoring.Thresholds // M3-A 等级阈值（默认=登记口径）
	paths    graph.PathQuery    // M3-B 攻击路径推演（MemPath/PGPath；nil=501）
	secrets  *secret.Service    // M3-C 密钥有效性验证（FR-CHN-002；未就绪=501）
	shadow   *shadowit.Service  // M3-C 影子 IT 收敛建议与纳管人审（FR-MIN-003；nil=501）
	evals    *evalset.Service   // M3-E 评测集与反馈门禁（FR-VRF-004/AIL-7；nil=501）
}

// SweepDispatcher 编排派发接缝（tdispatcher.Dispatcher 满足；SDK 类型不外泄，AX-6）。
type SweepDispatcher interface {
	Dispatch(ctx context.Context, sw *sweep.Sweep) error
}

// GraphQuery 抽象图谱读取（ingest.QueryService 满足）；解耦 httpapi 与 ingest 装配。
type GraphQuery interface {
	EntityByFingerprint(ctx context.Context, tenant, fp string) (graph.Entity, bool, error)
	Neighbors(ctx context.Context, tenant, fp string) ([]graph.Relation, error)
}

type Option func(*Server)

func WithGraph(g GraphQuery) Option         { return func(s *Server) { s.graph = g } }
func WithLedger(l *ledger.Service) Option   { return func(s *Server) { s.ledger = l } }
func WithSweep(sv *sweep.Service) Option    { return func(s *Server) { s.sweeps = sv } }
func WithAuthz(a *authz.Service) Option     { return func(s *Server) { s.authz = a } }
func WithPlugins(p *plugin.Registry) Option { return func(s *Server) { s.plugins = p } }

// WithScoring 注入 M3-A 评分口径（权重/阈值；未注入即默认登记口径，标注待 G8-01 定稿）。
func WithScoring(w scoring.Weights, th scoring.Thresholds) Option {
	return func(s *Server) { s.scoreW, s.scoreTh = w, th }
}

// WithPaths 注入 M3-B 路径推演（graph.PathQuery；未注入即 501 graph_path_unavailable）。
func WithPaths(p graph.PathQuery) Option { return func(s *Server) { s.paths = p } }
func WithKnowledge(v *vuln.Service, i *intel.Service, o *ownership.Service) Option {
	return func(s *Server) { s.vuln, s.intel, s.own = v, i, o }
}
func WithMonitor(m *monitor.Service) Option { return func(s *Server) { s.mon = m } }
func WithNotify(n *notify.Service) Option   { return func(s *Server) { s.notify = n } }
func WithEvidence(e evidence.Store) Option  { return func(s *Server) { s.evid = e } }
func WithCandidates(c *candidate.Service) Option {
	return func(s *Server) { s.cands = c }
}
func WithCollect(c *collect.Service) Option { return func(s *Server) { s.col = c } }
func WithDarkweb(d *darkweb.Service) Option { return func(s *Server) { s.dark = d } }
func WithWorkOrders(ws *workorder.Service) Option {
	return func(s *Server) { s.wos = ws }
}
func WithNotice(nn *notice.Service) Option { return func(s *Server) { s.not = nn } }
func WithReport(r *report.Service) Option  { return func(s *Server) { s.rpt = r } }
func WithSweepDispatcher(d SweepDispatcher) Option {
	return func(s *Server) { s.dispatch = d }
}

// WithSecret 注入 M3-C 密钥有效性验证（端点按 Ready() 判 501，不半可用）。
func WithSecret(sv *secret.Service) Option { return func(s *Server) { s.secrets = sv } }

// WithShadow 注入 M3-C 影子 IT 收敛建议与纳管人审面（nil=501 shadow_unavailable）。
func WithShadow(sh *shadowit.Service) Option { return func(s *Server) { s.shadow = sh } }

// WithEval 注入 M3-E 评测集与反馈门禁面（nil=501 eval_unavailable）。
func WithEval(ev *evalset.Service) Option { return func(s *Server) { s.evals = ev } }

func New(t *tenant.Service, a *asset.Service, tokens map[string]rbac.Principal, opts ...Option) *Server {
	s := &Server{
		tenants: t, assets: a, tokens: tokens,
		cls:    classify.New(),
		ledger: ledger.NewService(ledger.NewMemStore(), &audit.MemLog{}),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("GET /v1/tenants", s.auth(s.handleListTenants))
	mux.Handle("POST /v1/tenants", s.auth(s.handleCreateTenant))
	mux.Handle("GET /v1/tenants/{id}/assets", s.auth(s.handleListAssets))
	mux.Handle("POST /v1/tenants/{id}/assets", s.auth(s.handleCreateAsset))
	mux.Handle("GET /v1/assets/{id}", s.auth(s.handleGetAsset))
	mux.Handle("GET /v1/graph/entities/{id}", s.auth(s.handleGraphEntity))
	mux.Handle("POST /v1/graph/query", s.auth(s.handleGraphQuery))
	mux.Handle("GET /v1/classify/rules", s.auth(s.handleClassifyRules))
	mux.Handle("POST /v1/classify:detect", s.auth(s.handleClassifyDetect))
	mux.Handle("GET /v1/ledger", s.auth(s.handleListLedger))
	mux.Handle("POST /v1/tenants/{id}/ledger", s.auth(s.handleCreateLedger))
	mux.Handle("POST /v1/ledger/{id}/actions", s.auth(s.handleLedgerAction))
	mux.Handle("POST /v1/ledger/{id}/verify", s.auth(s.handleLedgerVerify))
	mux.Handle("POST /v1/ledger/{id}/notify", s.auth(s.handleLedgerNotify))
	mux.Handle("POST /v1/sweeps", s.auth(s.handleCreateSweep))
	mux.Handle("GET /v1/sweeps", s.auth(s.handleListSweeps))
	mux.Handle("GET /v1/sweeps/matrix", s.auth(s.handleSweepMatrix))
	mux.Handle("GET /v1/sweeps/{id}", s.auth(s.handleGetSweep))
	mux.Handle("GET /v1/syntax", s.auth(s.handleSyntaxList))
	mux.Handle("POST /v1/syntax:render", s.auth(s.handleSyntaxRender))
	mux.Handle("POST /v1/tenants/{id}/authz", s.auth(s.handleUpsertAuthz))
	mux.Handle("GET /v1/tenants/{id}/authz", s.auth(s.handleGetAuthz))
	mux.Handle("POST /v1/authz:check", s.auth(s.handleAuthzCheck))
	mux.Handle("GET /v1/plugins", s.auth(s.handleListPlugins))
	mux.Handle("POST /v1/plugins", s.auth(s.handleRegisterPlugin))
	mux.Handle("DELETE /v1/plugins/{id}", s.auth(s.handleUnregisterPlugin))
	mux.Handle("GET /v1/vuln-library", s.auth(s.handleListVulns))
	mux.Handle("POST /v1/vuln-library/import", s.auth(s.handleImportVulns))
	mux.Handle("GET /v1/vuln-library/{cve}", s.auth(s.handleVulnDetail))
	mux.Handle("GET /v1/intel", s.auth(s.handleListIntel))
	mux.Handle("POST /v1/intel/import", s.auth(s.handleImportIntel))
	mux.Handle("GET /v1/intel/hits", s.auth(s.handleIntelHits))
	mux.Handle("POST /v1/ownership:judge", s.auth(s.handleOwnershipJudge))
	mux.Handle("POST /v1/tenants/{id}/ownership/fingerprints", s.auth(s.handleUpsertFingerprints))
	mux.Handle("GET /v1/tenants/{id}/ownership/fingerprints", s.auth(s.handleGetFingerprints))
	mux.Handle("GET /v1/ownership/queue", s.auth(s.handleOwnershipQueue))
	mux.Handle("POST /v1/ownership/queue/{seq}/resolve", s.auth(s.handleOwnershipResolve))
	mux.Handle("GET /v1/alerts", s.auth(s.handleListAlerts))
	mux.Handle("GET /v1/monitors", s.auth(s.handleListMonitors))
	mux.Handle("POST /v1/monitors", s.auth(s.handleCreateMonitor))
	mux.Handle("POST /v1/monitors/{id}/run", s.auth(s.handleRunMonitor))
	mux.Handle("POST /v1/alerts:dispatch", s.auth(s.handleDispatchAlerts))
	mux.Handle("GET /v1/alerts/channels", s.auth(s.handleNotifyChannels))
	mux.Handle("POST /v1/evidence", s.auth(s.handlePutEvidence))
	mux.Handle("GET /v1/evidence", s.auth(s.handleGetEvidence))
	mux.Handle("POST /v1/candidates:ingest", s.auth(s.handleIngestCandidates))
	mux.Handle("GET /v1/candidates/unsupported", s.auth(s.handleListUnsupported))
	// V-9：摄取留痕（PG 模式跨重启；行级租户闸在 handler 内）
	mux.Handle("GET /v1/tenants/{id}/candidates/accepted", s.auth(s.handleListAcceptedCandidates))
	mux.Handle("POST /v1/tenants/{id}/scan:repo", s.auth(s.handleScanRepo))
	mux.Handle("POST /v1/tenants/{id}/scan:port", s.auth(s.handleScanPort))
	mux.Handle("POST /v1/tenants/{id}/scan:dir", s.auth(s.handleScanDir))
	mux.Handle("POST /v1/tenants/{id}/darkweb:inspect", s.auth(s.handleDarkwebInspect))
	mux.Handle("GET /v1/tenants/{id}/darkweb/packages", s.auth(s.handleListLeadPackages))
	mux.Handle("GET /v1/tenants/{id}/darkweb/packages/{pid}", s.auth(s.handleGetLeadPackage))
	mux.Handle("GET /v1/tenants/{id}/darkweb/packages/{pid}/export", s.auth(s.handleExportLeadPackage))
	mux.Handle("GET /v1/tenants/{id}/assets/{aid}/score", s.auth(s.handleAssetScore))
	mux.Handle("GET /v1/tenants/{id}/scoring/weights", s.auth(s.handleScoringWeights))
	mux.Handle("GET /v1/tenants/{id}/graph/paths", s.auth(s.handleGraphShortestPath))
	mux.Handle("GET /v1/tenants/{id}/graph/reach", s.auth(s.handleGraphReachable))
	mux.Handle("GET /v1/tenants/{id}/graph/subgraph", s.auth(s.handleGraphSubgraph))
	mux.Handle("GET /v1/tenants/{id}/graph/top-paths", s.auth(s.handleGraphTopPaths))
	mux.Handle("POST /v1/tenants/{id}/secret:verify", s.auth(s.handleSecretVerify))
	mux.Handle("GET /v1/tenants/{id}/secret/metrics", s.auth(s.handleSecretMetrics))
	mux.Handle("POST /v1/tenants/{id}/shadow:advise", s.auth(s.handleShadowAdvise))
	mux.Handle("POST /v1/tenants/{id}/shadow/admit", s.auth(s.handleShadowAdmit))
	// M3-E 评测集与反馈门禁（WP-M3-06 / FR-VRF-004 / AIL-7）
	mux.Handle("GET /v1/tenants/{id}/evalset/samples", s.auth(s.handleEvalSamplesList))
	mux.Handle("POST /v1/tenants/{id}/evalset/samples", s.auth(s.handleEvalSamplesAdd))
	mux.Handle("POST /v1/tenants/{id}/evalset/relabel", s.auth(s.handleEvalRelabel))
	mux.Handle("POST /v1/tenants/{id}/evalset/reflux", s.auth(s.handleEvalReflux))
	mux.Handle("POST /v1/tenants/{id}/evalset:run", s.auth(s.handleEvalRun))
	mux.Handle("GET /v1/tenants/{id}/evalset/runs", s.auth(s.handleEvalRuns))
	mux.Handle("GET /v1/tenants/{id}/evalset/gate", s.auth(s.handleEvalGate))
	mux.Handle("POST /v1/tenants/{id}/workorders", s.auth(s.handleCreateWorkOrder))
	mux.Handle("GET /v1/tenants/{id}/workorders", s.auth(s.handleListWorkOrders))
	mux.Handle("GET /v1/tenants/{id}/workorders/{wid}", s.auth(s.handleGetWorkOrder))
	mux.Handle("POST /v1/tenants/{id}/workorders/{wid}/advance", s.auth(s.handleAdvanceWorkOrder))
	mux.Handle("POST /v1/tenants/{id}/notices", s.auth(s.handleCreateNotice))
	mux.Handle("GET /v1/tenants/{id}/notices", s.auth(s.handleListNotices))
	mux.Handle("GET /v1/tenants/{id}/notices/overdue", s.auth(s.handleOverdueNotices))
	mux.Handle("GET /v1/tenants/{id}/notices/{nid}/material", s.auth(s.handleNoticeMaterial))
	mux.Handle("GET /v1/tenants/{id}/notices/{nid}/chain", s.auth(s.handleNoticeChain))
	mux.Handle("POST /v1/tenants/{id}/notices/{nid}/receipt", s.auth(s.handleNoticeReceipt))
	mux.Handle("GET /v1/tenants/{id}/report:summary", s.auth(s.handleSummaryReport))
	mux.Handle("POST /v1/tenants/{id}/reports", s.auth(s.handleGenerateReport))
	mux.Handle("GET /v1/tenants/{id}/reports", s.auth(s.handleListReports))
	mux.Handle("GET /v1/tenants/{id}/reports/{rid}", s.auth(s.handleGetReport))
	mux.Handle("GET /v1/tenants/{id}/reports/{rid}/export", s.auth(s.handleExportReport))
	return mux
}

// ---- 中间件与工具 ----

func (s *Server) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := newRequestID()
		tok := bearerToken(r)
		p, ok := s.tokens[tok]
		if !ok {
			writeError(w, rid, http.StatusUnauthorized, "unauthenticated", "missing or invalid token")
			return
		}
		ctx := context.WithValue(r.Context(), keyPrincipal, p)
		ctx = context.WithValue(ctx, keyRequestID, rid)
		next(w, r.WithContext(ctx))
	})
}

func principalOf(r *http.Request) rbac.Principal {
	p, _ := r.Context().Value(keyPrincipal).(rbac.Principal)
	return p
}

func requestIDOf(r *http.Request) string {
	rid, _ := r.Context().Value(keyRequestID).(string)
	return rid
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && h[:len(prefix)] == prefix {
		return h[len(prefix):]
	}
	return ""
}

func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type errEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, rid string, status int, code, msg string) {
	var e errEnvelope
	e.Error.Code = code
	e.Error.Message = msg
	e.Error.RequestID = rid
	writeJSON(w, status, e)
}

// mapErr 把领域错误映射为 HTTP 状态与错误码（SRS IR 统一约定）。
func mapErr(err error) (int, string) {
	if st, code, ok := evStatus(err); ok { // 证据层（ENH-05）：NotFound/Immutable/Empty/BadKey/BadRef
		return st, code
	}
	switch {
	case errors.Is(err, rbac.ErrCrossTenant):
		return http.StatusForbidden, "cross_tenant_denied"
	case errors.Is(err, rbac.ErrForbidden):
		return http.StatusForbidden, "forbidden"
	case errors.Is(err, tenant.ErrNotFound), errors.Is(err, asset.ErrNotFound), errors.Is(err, ledger.ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, tenant.ErrDuplicate), errors.Is(err, asset.ErrDuplicate), errors.Is(err, ledger.ErrDuplicate):
		return http.StatusConflict, "duplicate"
	case errors.Is(err, tenant.ErrInvalid), errors.Is(err, asset.ErrInvalid), errors.Is(err, ledger.ErrInvalid), errors.Is(err, sweep.ErrUnknownPhase):
		return http.StatusBadRequest, "invalid_request"
	case errors.Is(err, ledger.ErrState):
		return http.StatusUnprocessableEntity, "illegal_state_transition"
	case errors.Is(err, syntax.ErrInvalidInput):
		return http.StatusBadRequest, "invalid_request"
	case errors.Is(err, authz.ErrInvalidScope):
		return http.StatusBadRequest, "invalid_scope"
	case errors.Is(err, authz.ErrNoScope):
		return http.StatusForbidden, "no_valid_scope"
	case errors.Is(err, authz.ErrNotInWindow):
		return http.StatusForbidden, "not_in_time_window"
	case errors.Is(err, authz.ErrNotInScope):
		return http.StatusForbidden, "not_in_scope"
	case errors.Is(err, authz.ErrNoSecondAuth):
		return http.StatusForbidden, "second_auth_required"
	case errors.Is(err, plugin.ErrContract):
		return http.StatusUnprocessableEntity, "invalid_contract"
	case errors.Is(err, evalset.ErrInvalid), errors.Is(err, evalset.ErrNoSamples):
		return http.StatusBadRequest, "invalid_request"
	case errors.Is(err, evalset.ErrSampleNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, workorder.ErrInvalid):
		return http.StatusBadRequest, "invalid_request"
	case errors.Is(err, workorder.ErrIllegalTransition):
		return http.StatusUnprocessableEntity, "illegal_state_transition"
	case errors.Is(err, workorder.ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, workorder.ErrDuplicate):
		return http.StatusConflict, "duplicate"
	case errors.Is(err, notice.ErrInvalid):
		return http.StatusBadRequest, "invalid_request"
	case errors.Is(err, notice.ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, notice.ErrDuplicate):
		return http.StatusConflict, "duplicate"
	case errors.Is(err, notice.ErrLocked):
		return http.StatusUnprocessableEntity, "notice_locked"
	case errors.Is(err, report.ErrInvalid):
		return http.StatusBadRequest, "invalid_request"
	case errors.Is(err, report.ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, plugin.ErrDuplicate):
		return http.StatusConflict, "duplicate"
	case errors.Is(err, plugin.ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, monitor.ErrKind):
		return http.StatusBadRequest, "invalid_request"
	case errors.Is(err, monitor.ErrNotFound):
		return http.StatusNotFound, "not_found"
	default:
		return http.StatusInternalServerError, "internal"
	}
}

func failFrom(w http.ResponseWriter, r *http.Request, err error) {
	status, code := mapErr(err)
	msg := err.Error()
	if code == "internal" {
		// fail loud：500 细节记录到服务端日志，响应体不回显内部信息
		slog.Error("internal error", "request_id", requestIDOf(r), "path", r.URL.Path, "err", msg)
		msg = "internal server error"
	}
	writeError(w, requestIDOf(r), status, code, msg)
}

// ---- JSON 模型（snake_case 对齐 DR-01 / DR-07）----

type tenantInput struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Short       string   `json:"short,omitempty"`
	Industry    string   `json:"industry,omitempty"`
	Level       string   `json:"level,omitempty"`
	Plan        string   `json:"plan,omitempty"`
	RootDomains []string `json:"root_domains,omitempty"`
	CIDRs       []string `json:"cidrs,omitempty"`
	Contact     string   `json:"contact,omitempty"`
	Region      string   `json:"region,omitempty"`
	ThemeColor  string   `json:"theme_color,omitempty"`
	Status      string   `json:"status,omitempty"`
}

type tenantView struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Short       string   `json:"short,omitempty"`
	Industry    string   `json:"industry,omitempty"`
	Status      string   `json:"status"`
	ThemeColor  string   `json:"theme_color,omitempty"`
	Region      string   `json:"region,omitempty"`
	ContractEnd string   `json:"contract_end,omitempty"`
	RootDomains []string `json:"root_domains,omitempty"`
	CIDRs       []string `json:"cidrs,omitempty"`
}

func toTenantView(t tenant.Tenant) tenantView {
	v := tenantView{ID: t.ID, Name: t.Name, Short: t.Short, Industry: t.Industry, Status: t.Status, ThemeColor: t.ThemeColor, Region: t.Region, RootDomains: t.RootDomains, CIDRs: t.CIDRs}
	if !t.ContractEnd.IsZero() {
		v.ContractEnd = t.ContractEnd.UTC().Format(time.RFC3339)
	}
	return v
}

type assetInput struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	TypeLabel string   `json:"type_label,omitempty"`
	IP        string   `json:"ip,omitempty"`
	Risk      string   `json:"risk"`
	Exp       int      `json:"exp"`
	Owner     string   `json:"owner"`
	Found     string   `json:"found"`
	Status    string   `json:"status"`
	Beian     string   `json:"beian"`
	Source    string   `json:"source"`
	Biz       string   `json:"biz"`
	Tags      []string `json:"tags,omitempty"`
	Ports     []int    `json:"ports,omitempty"`
	Tech      []string `json:"tech,omitempty"`
}

type assetView struct {
	ID        string   `json:"id"`
	Tenant    string   `json:"tenant"`
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	TypeLabel string   `json:"type_label,omitempty"`
	IP        string   `json:"ip,omitempty"`
	Risk      string   `json:"risk"`
	Exp       int      `json:"exp"`
	Owner     string   `json:"owner"`
	Found     string   `json:"found"`
	Status    string   `json:"status"`
	Beian     string   `json:"beian"`
	Source    string   `json:"source"`
	Biz       string   `json:"biz"`
	Tags      []string `json:"tags,omitempty"`
	AI        string   `json:"ai,omitempty"`
	Ports     []int    `json:"ports,omitempty"`
	Tech      []string `json:"tech,omitempty"`
}

func toAssetView(a asset.Asset) assetView {
	return assetView{
		ID: a.ID, Tenant: a.Tenant, Name: a.Name, Type: a.Type, TypeLabel: a.TypeLabel,
		IP: a.IP, Risk: a.Risk, Exp: a.Exp, Owner: a.Owner,
		Found:  a.Found.UTC().Format(time.RFC3339),
		Status: a.Status, Beian: a.Beian, Source: a.Source, Biz: a.Biz,
		Tags: a.Tags, AI: a.AI, Ports: a.Ports, Tech: a.Tech,
	}
}

// ---- handlers ----

func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	list, err := s.tenants.List(r.Context(), principalOf(r))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	views := make([]tenantView, 0, len(list))
	for _, t := range list {
		views = append(views, toTenantView(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views, "total": len(views)})
}

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var in tenantInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	t := tenant.Tenant{
		ID: in.ID, Name: in.Name, Short: in.Short, Industry: in.Industry,
		Level: in.Level, Plan: in.Plan, RootDomains: in.RootDomains, CIDRs: in.CIDRs,
		Contact: in.Contact, Region: in.Region, ThemeColor: in.ThemeColor,
		Status: in.Status,
	}
	if t.Status == "" {
		t.Status = "active"
	}
	if err := s.tenants.Create(r.Context(), principalOf(r), requestIDOf(r), t); err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toTenantView(t))
}

// parsePage 实现 IR 统一分页约定：默认 1/50，上限 500。
func parsePage(r *http.Request) (page, size int) {
	page, size = 1, 50
	if v, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && v > 0 {
		page = v
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("page_size")); err == nil && v > 0 {
		size = v
	}
	if size > 500 {
		size = 500
	}
	return
}

func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("id")
	list, err := s.assets.ListByTenant(r.Context(), principalOf(r), requestIDOf(r), tenantID)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	page, size := parsePage(r)
	total := len(list)
	start := (page - 1) * size
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	views := make([]assetView, 0, end-start)
	for _, a := range list[start:end] {
		views = append(views, toAssetView(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views, "total": total, "page": page, "page_size": size})
}

func (s *Server) handleCreateAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("id")
	var in assetInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return
	}
	a := asset.Asset{
		ID: in.ID, Tenant: tenantID, Name: in.Name, Type: in.Type, TypeLabel: in.TypeLabel,
		IP: in.IP, Risk: in.Risk, Exp: in.Exp, Owner: in.Owner, Status: in.Status,
		Beian: in.Beian, Source: in.Source, Biz: in.Biz, Tags: in.Tags, Ports: in.Ports, Tech: in.Tech,
	}
	if in.Found != "" {
		ts, err := time.Parse(time.RFC3339, in.Found)
		if err != nil {
			writeError(w, requestIDOf(r), http.StatusBadRequest, "invalid_request", "found 必须为 ISO 8601/RFC3339")
			return
		}
		a.Found = ts
	}
	created, err := s.assets.Create(r.Context(), principalOf(r), requestIDOf(r), a)
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toAssetView(created))
}

func (s *Server) handleGetAsset(w http.ResponseWriter, r *http.Request) {
	a, err := s.assets.GetByID(r.Context(), principalOf(r), requestIDOf(r), r.PathValue("id"))
	if err != nil {
		failFrom(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toAssetView(a))
}
