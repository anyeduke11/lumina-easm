// Package app 是服务端的组装根：把领域服务、HTTP/MCP/静态面装配成一个 Handler
// （WP-M0-02/WP-M0-07；替代 main 中 28 参数的 newRouter）。
package app

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/alert"
	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/authn"
	"github.com/wangdev88/easm-platform/platform/services/internal/authz"
	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
	"github.com/wangdev88/easm-platform/platform/services/internal/collect"
	"github.com/wangdev88/easm-platform/platform/services/internal/confirm"
	"github.com/wangdev88/easm-platform/platform/services/internal/darkweb"
	"github.com/wangdev88/easm-platform/platform/services/internal/detect"
	"github.com/wangdev88/easm-platform/platform/services/internal/discovery"
	"github.com/wangdev88/easm-platform/platform/services/internal/evalset"
	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/finding"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/httpapi"
	"github.com/wangdev88/easm-platform/platform/services/internal/intel"
	"github.com/wangdev88/easm-platform/platform/services/internal/inventory"
	"github.com/wangdev88/easm-platform/platform/services/internal/job"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/mcp"
	"github.com/wangdev88/easm-platform/platform/services/internal/mm"
	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
	"github.com/wangdev88/easm-platform/platform/services/internal/notice"
	"github.com/wangdev88/easm-platform/platform/services/internal/notify"
	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
	"github.com/wangdev88/easm-platform/platform/services/internal/plugin"
	"github.com/wangdev88/easm-platform/platform/services/internal/projection"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/report"
	"github.com/wangdev88/easm-platform/platform/services/internal/scoring"
	"github.com/wangdev88/easm-platform/platform/services/internal/secret"
	"github.com/wangdev88/easm-platform/platform/services/internal/shadowit"
	"github.com/wangdev88/easm-platform/platform/services/internal/sweep"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
	"github.com/wangdev88/easm-platform/platform/services/internal/usage"
	"github.com/wangdev88/easm-platform/platform/services/internal/vuln"
	"github.com/wangdev88/easm-platform/platform/services/internal/workorder"
)

// Deps 是组装根依赖快照。字段为 nil 表示该能力未装配（对应端点 501）。
type Deps struct {
	Tenants   *tenant.Service
	Assets    *asset.Service
	Ledger    *ledger.Service
	Sweep     *sweep.Service
	Authz     *authz.Service
	Plugins   *plugin.Registry
	Vuln      *vuln.Service
	Intel     *intel.Service
	Ownership *ownership.Service
	Monitor   *monitor.Service
	Notify    *notify.Service
	Evidence  evidence.Store
	Candidate *candidate.Service
	Collect   *collect.Service
	Darkweb   *darkweb.Service
	WorkOrder *workorder.Service
	Notice    *notice.Service
	Report    *report.Service

	Dispatcher httpapi.SweepDispatcher
	Tokens     map[string]rbac.Principal

	GraphQuery httpapi.GraphQuery
	PathQuery  graph.PathQuery
	Secret     *secret.Service
	Shadow     *shadowit.Service
	Eval       *evalset.Service
	MM         *mm.Service
	Usage      *usage.Service

	Confirm         *confirm.Service
	ConfirmRequired bool
	OIDC            *authn.OIDC
	BreakGlass      *authn.BreakGlass
	Passkey         *authn.Passkey
	Inventory       *inventory.Service
	Findings        *finding.Service
	Jobs            *job.Service
	Discovery       *discovery.Service
	Projection      *projection.Projector
	Alerts          *alert.Service
	Detector        *detect.Detector
	AssetStale      time.Duration
	AssetRetire     time.Duration

	ScoreWeights    scoring.Weights
	ScoreThresholds scoring.Thresholds

	Audit      audit.Log
	ConsoleDir string
	Ready      func(context.Context) error // /readyz 依赖探活（PG Ping 等）；nil=内存模式
}

// Handler 组装 REST（/v1/*、/healthz）、MCP（/mcp）与 console 静态面。
func (d Deps) Handler() http.Handler {
	api := httpapi.New(d.Tenants, d.Assets, d.Tokens,
		httpapi.WithGraph(d.GraphQuery),
		httpapi.WithLedger(d.Ledger),
		httpapi.WithSweep(d.Sweep),
		httpapi.WithAuthz(d.Authz),
		httpapi.WithPlugins(d.Plugins),
		httpapi.WithKnowledge(d.Vuln, d.Intel, d.Ownership),
		httpapi.WithMonitor(d.Monitor),
		httpapi.WithNotify(d.Notify),
		httpapi.WithEvidence(d.Evidence),
		httpapi.WithCandidates(d.Candidate),
		httpapi.WithCollect(d.Collect),
		httpapi.WithDarkweb(d.Darkweb),
		httpapi.WithWorkOrders(d.WorkOrder),
		httpapi.WithNotice(d.Notice),
		httpapi.WithReport(d.Report),
		httpapi.WithSweepDispatcher(d.Dispatcher),
		httpapi.WithScoring(d.ScoreWeights, d.ScoreThresholds),
		httpapi.WithPaths(d.PathQuery),
		httpapi.WithSecret(d.Secret),
		httpapi.WithShadow(d.Shadow),
		httpapi.WithEval(d.Eval),
		httpapi.WithMM(d.MM),
		httpapi.WithUsage(d.Usage),
		httpapi.WithConfirmation(d.Confirm, d.ConfirmRequired),
		httpapi.WithAudit(d.Audit),
		httpapi.WithReady(d.Ready),
		httpapi.WithOIDC(d.OIDC),
		httpapi.WithBreakGlass(d.BreakGlass),
		httpapi.WithPasskey(d.Passkey),
		httpapi.WithInventory(d.Inventory),
		httpapi.WithFindings(d.Findings),
		httpapi.WithJobs(d.Jobs),
		httpapi.WithDiscovery(d.Discovery),
		httpapi.WithProjection(d.Projection),
		httpapi.WithAlerts(d.Alerts),
		httpapi.WithDetector(d.Detector),
		httpapi.WithAssetDecay(d.AssetStale, d.AssetRetire),
	).Handler()

	mcpH := mcp.New(d.Tenants, d.Assets, d.Tokens,
		mcp.WithLedger(d.Ledger),
		mcp.WithSweep(d.Sweep),
		mcp.WithMonitor(d.Monitor),
		mcp.WithWorkOrders(d.WorkOrder),
		mcp.WithNotices(d.Notice),
		mcp.WithReport(d.Report),
		mcp.WithPaths(d.PathQuery),
		mcp.WithVulnIntel(d.Vuln, d.Intel),
		mcp.WithCollect(d.Collect),
		mcp.WithConfirmation(d.Confirm, d.ConfirmRequired),
		mcp.WithAudit(d.Audit),
		mcp.WithOIDC(d.OIDC),
		mcp.WithBreakGlass(d.BreakGlass),
	).Handler()

	console := http.FileServer(http.Dir(d.ConsoleDir))
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcpH)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if isAPIPath(p) {
			api.ServeHTTP(w, r)
			return
		}
		console.ServeHTTP(w, r)
	})
	return mux
}

// isAPIPath 顶层分流白名单：API 路由表新增无 /v1 前缀的端点时必须同步这里，
// 否则请求会被静态面吞掉（/readyz 曾实测 404）。
func isAPIPath(p string) bool {
	return strings.HasPrefix(p, "/v1/") || p == "/healthz" || p == "/readyz"
}
