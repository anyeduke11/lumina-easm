// Package report 实现报告中心（WP-M2-09 / FR-RPT-001~004）。
// 报告由所选租户的实时事实聚合生成（风险台账/资产/暗网线索包/处置工单/线索通报），
// 周期窗口、受众、章节均为参数；禁止静态文案与随机编号（A-05：切客户全变）。
// 确定性切片先行：AI 动态内容（ENH-10）未触达前，执行摘要为四受众差异化的确定性话术。
// 历史记录 PG 化（013_report.sql / pgstore.ReportStore，V-3：报告=对外交付物，重启不丢）；
// 内存模式仍为 MemStore（同契约 C-6，供单测与无 PG 演示）。
// PDF 导出本期不交付（FR-RPT-004 过渡形态：md/json 后端直出，PDF 登记遗留）。
package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/darkweb"
	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/notice"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
	"github.com/wangdev88/easm-platform/platform/services/internal/workorder"
)

const (
	PeriodD7      = "d7"      // 近 7 天
	PeriodD30     = "d30"     // 近 30 天
	PeriodQuarter = "quarter" // 本季度（自然季度：Q1=1-3/Q2=4-6/Q3=7-9/Q4=10-12）
)

// 受众（FR-RPT-003：四受众执行摘要首段明显不同）。
const (
	AudExec       = "exec"
	AudOps        = "ops"
	AudCompliance = "compliance"
	AudRedteam    = "redteam"
)

// 八章节键（与控制台 REPORT_SECTIONS 一致）。
const (
	SecExec     = "exec"     // 执行摘要
	SecKPI      = "kpi"      // 关键指标
	SecRisk     = "risk"     // 风险资产清单
	SecPath     = "path"     // 攻击路径推演
	SecVuln     = "vuln"     // 漏洞影响面
	SecIntel    = "intel"    // 情报命中
	SecAdvice   = "advice"   // 处置建议与路线图
	SecAppendix = "appendix" // 附录：数据源与覆盖
)

// SectionOrder 章节固定顺序（渲染与输出都按此序）。
var SectionOrder = []string{SecExec, SecKPI, SecRisk, SecPath, SecVuln, SecIntel, SecAdvice, SecAppendix}

var periods = map[string]bool{PeriodD7: true, PeriodD30: true, PeriodQuarter: true}
var audiences = map[string]bool{AudExec: true, AudOps: true, AudCompliance: true, AudRedteam: true}

var (
	ErrInvalid  = errors.New("report: 报告参数非法")
	ErrNotFound = errors.New("report: 报告不存在")
)

// Params 报告生成参数（FR-RPT-001）。
type Params struct {
	Tenant   string   `json:"tenant"`
	Period   string   `json:"period"`
	Audience string   `json:"audience"`
	Sections []string `json:"sections"` // 空=全八章节
}

// Report 一份已生成报告（历史记录=参数+正文快照+哈希；内容可复算）。
type Report struct {
	ID          string    `json:"id"` // RPT-<hash12(tenant|period|audience|sections|window_from)>
	Tenant      string    `json:"tenant"`
	TenantName  string    `json:"tenant_name"`
	Period      string    `json:"period"`
	Audience    string    `json:"audience"`
	Sections    []string  `json:"sections"`
	PeriodFrom  time.Time `json:"period_from"`
	PeriodTo    time.Time `json:"period_to"`
	GeneratedAt time.Time `json:"generated_at"`
	Text        string    `json:"text"`         // 选中章节拼接的 Markdown
	ContentHash string    `json:"content_hash"` // 正文 SHA-256
	EvidenceRef string    `json:"evidence_ref,omitempty"`
}

// ---- 实时数据读口（主体作用域由各 Service 内部保证）----

type tenantReader interface {
	Get(ctx context.Context, p rbac.Principal, reqID, id string) (tenant.Tenant, error)
}
type ledgerLister interface {
	List(ctx context.Context, p rbac.Principal, reqID string, f ledger.Filter) ([]ledger.Item, error)
}
type assetLister interface {
	ListByTenant(ctx context.Context, p rbac.Principal, reqID, tenantID string) ([]asset.Asset, error)
}
type packageLister interface {
	ListPackages(ctx context.Context, tenant string) ([]darkweb.LeadPackage, error)
}
type workOrderLister interface {
	List(ctx context.Context, p rbac.Principal, reqID, tenant, status string) ([]workorder.WorkOrder, error)
}
type noticeLister interface {
	List(ctx context.Context, p rbac.Principal, reqID, tenant, status string) ([]notice.Notice, error)
}

type Store interface {
	Save(ctx context.Context, r Report) error
	Get(ctx context.Context, tenant, id string) (Report, error) // 租户不匹配=ErrNotFound（行级闸）
	List(ctx context.Context, tenant string) ([]Report, error)
}

// MemStore 内存模式历史形态：进程内保存，重启清空（PG 模式由 pgstore.ReportStore 承接，013）。
type MemStore struct {
	mu sync.RWMutex
	m  map[string]Report
}

func NewMemStore() *MemStore { return &MemStore{m: map[string]Report{}} }

func (s *MemStore) Save(_ context.Context, r Report) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[r.ID] = r // 同参数同窗重放=覆盖刷新（编号幂等，内容取最新事实）
	return nil
}

func (s *MemStore) Get(_ context.Context, tenant, id string) (Report, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.m[id]
	if !ok || r.Tenant != tenant {
		return Report{}, ErrNotFound
	}
	return r, nil
}

func (s *MemStore) List(_ context.Context, tenant string) ([]Report, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Report, 0)
	for _, r := range s.m {
		if r.Tenant == tenant {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GeneratedAt.After(out[j].GeneratedAt) })
	return out, nil
}

type Service struct {
	store Store
	log   audit.Log
	ten   tenantReader
	led   ledgerLister
	ast   assetLister
	pkgs  packageLister
	wos   workOrderLister
	nots  noticeLister
	ev    evidence.Store
	now   func() time.Time
}

func NewService(store Store, log audit.Log, ten tenantReader, led ledgerLister) *Service {
	return &Service{store: store, log: log, ten: ten, led: led, now: time.Now}
}

func (s *Service) WithAssets(a assetLister)         { s.ast = a }
func (s *Service) WithPackages(p packageLister)     { s.pkgs = p }
func (s *Service) WithWorkOrders(w workOrderLister) { s.wos = w }
func (s *Service) WithNotices(n noticeLister)       { s.nots = n }
func (s *Service) WithEvidence(ev evidence.Store)   { s.ev = ev }

// window 周期→[from,to] 时间窗（to=now；本季度从当季首日起）。
func window(now time.Time, period string) (time.Time, time.Time, error) {
	to := now.UTC()
	switch period {
	case PeriodD7:
		return to.AddDate(0, 0, -7), to, nil
	case PeriodD30:
		return to.AddDate(0, 0, -30), to, nil
	case PeriodQuarter:
		q0 := (int(to.Month()) - 1) / 3 * 3 // 季度首月（0基）
		return time.Date(to.Year(), time.Month(q0+1), 1, 0, 0, 0, 0, time.UTC), to, nil
	default:
		return time.Time{}, time.Time{}, fmt.Errorf("%w: period 须为 d7|d30|quarter", ErrInvalid)
	}
}

func normSections(in []string) ([]string, error) {
	if len(in) == 0 {
		out := make([]string, len(SectionOrder))
		copy(out, SectionOrder)
		return out, nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, k := range in { // 按入参顺序去重，再按固定序输出
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for _, k := range out {
		known := false
		for _, ok := range SectionOrder {
			if k == ok {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("%w: 未知章节 %q", ErrInvalid, k)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return idx(SectionOrder, out[i]) < idx(SectionOrder, out[j]) })
	return out, nil
}

func idx(xs []string, k string) int {
	for i, x := range xs {
		if x == k {
			return i
		}
	}
	return len(xs)
}

// Generate 实时聚合生成报告并保存历史（FR-RPT-001/002/003）。
func (s *Service) Generate(ctx context.Context, p rbac.Principal, reqID string, in Params) (Report, error) {
	var rep Report
	if !p.Can(rbac.PermReadAssets) {
		s.deny(ctx, p, "report.generate", in.Tenant, reqID)
		return rep, rbac.ErrForbidden
	}
	if !p.InScope(in.Tenant) {
		s.deny(ctx, p, "report.generate", in.Tenant, reqID)
		return rep, rbac.ErrCrossTenant
	}
	if !periods[in.Period] || !audiences[in.Audience] {
		return rep, fmt.Errorf("%w: period 须为 d7|d30|quarter 且 audience 须为 exec|ops|compliance|redteam", ErrInvalid)
	}
	secs, err := normSections(in.Sections)
	if err != nil {
		return rep, err
	}
	t, err := s.ten.Get(ctx, p, reqID, in.Tenant) // 未知租户=tenant.ErrNotFound（不泄露存在性的口径随租户服务）
	if err != nil {
		return rep, err
	}
	now := s.now().UTC()
	from, to, err := window(now, in.Period)
	if err != nil {
		return rep, err
	}
	d, err := s.gather(ctx, p, reqID, in.Tenant, from, to)
	if err != nil {
		return rep, err
	}
	rep = Report{
		ID:     "RPT-" + hash12(in.Tenant+"|"+in.Period+"|"+in.Audience+"|"+strings.Join(secs, ",")+"|"+from.Format("20060102")),
		Tenant: in.Tenant, TenantName: t.Name, Period: in.Period, Audience: in.Audience, Sections: secs,
		PeriodFrom: from, PeriodTo: to, GeneratedAt: now,
	}
	rep.Text = render(rep, d)
	rep.ContentHash = sha256hex([]byte(rep.Text))
	if s.ev != nil { // 正文固化（与 notice 同范式；固化失败不阻断，空 ref=显式降级）
		key := "report/" + in.Tenant + "/" + rep.ID + "-" + hash12(rep.ContentHash) + ".md"
		ref, perr := s.ev.Put(ctx, key, []byte(rep.Text))
		switch {
		case errors.Is(perr, evidence.ErrImmutable):
			rep.EvidenceRef = s.ev.RefOf(key)
		case perr == nil:
			rep.EvidenceRef = ref
		}
	}
	if err := s.store.Save(ctx, rep); err != nil {
		return rep, err
	}
	s.allow(ctx, p, "report.generate", in.Tenant, rep.ID, reqID)
	return rep, nil
}

// facts 报告聚合事实集（全部为实时读数；窗口裁剪只作用于台账条目）。
type facts struct {
	items   []ledger.Item // 周期内（按 Found 裁剪）
	assets  []asset.Asset // 租户全量资产（暴露面现状不受窗口限制）
	pkgs    []darkweb.LeadPackage
	wos     []workorder.WorkOrder
	notices []notice.Notice
}

func (s *Service) gather(ctx context.Context, p rbac.Principal, reqID, tenant string, from, to time.Time) (facts, error) {
	var d facts
	items, err := s.led.List(ctx, p, reqID, ledger.Filter{Tenant: tenant})
	if err != nil {
		return d, err
	}
	for _, it := range items { // ledger.Filter 无时间窗（Rule：在本包按 Found 裁剪）
		f := it.Found.UTC()
		if (f.After(from) || f.Equal(from)) && (f.Before(to) || f.Equal(to)) {
			d.items = append(d.items, it)
		}
	}
	if s.ast != nil {
		if d.assets, err = s.ast.ListByTenant(ctx, p, reqID, tenant); err != nil {
			return d, err
		}
	}
	if s.pkgs != nil {
		if d.pkgs, err = s.pkgs.ListPackages(ctx, tenant); err != nil {
			return d, err
		}
	}
	if s.wos != nil {
		if d.wos, err = s.wos.List(ctx, p, reqID, tenant, ""); err != nil {
			return d, err
		}
	}
	if s.nots != nil {
		if d.notices, err = s.nots.List(ctx, p, reqID, tenant, ""); err != nil {
			return d, err
		}
	}
	return d, nil
}

// Get 行级租户读报告。
func (s *Service) Get(ctx context.Context, p rbac.Principal, reqID, tenant, id string) (Report, error) {
	if !p.Can(rbac.PermReadAssets) {
		s.deny(ctx, p, "report.read", tenant, reqID)
		return Report{}, rbac.ErrForbidden
	}
	if !p.InScope(tenant) {
		s.deny(ctx, p, "report.read", tenant, reqID)
		return Report{}, rbac.ErrCrossTenant
	}
	r, err := s.store.Get(ctx, tenant, id)
	if err != nil {
		return Report{}, err
	}
	s.allow(ctx, p, "report.read", tenant, id, reqID)
	return r, nil
}

// List 行级租户列历史（参数组合历史，FR-RPT-001 验收）。
func (s *Service) List(ctx context.Context, p rbac.Principal, reqID, tenant string) ([]Report, error) {
	if !p.Can(rbac.PermReadAssets) {
		s.deny(ctx, p, "report.list", tenant, reqID)
		return nil, rbac.ErrForbidden
	}
	if !p.InScope(tenant) {
		s.deny(ctx, p, "report.list", tenant, reqID)
		return nil, rbac.ErrCrossTenant
	}
	return s.store.List(ctx, tenant)
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hash12(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6])
}

func (s *Service) deny(ctx context.Context, p rbac.Principal, action, tenant, reqID string) {
	_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: action, TenantID: tenant, Result: audit.ResultDeny, RequestID: reqID})
}

func (s *Service) allow(ctx context.Context, p rbac.Principal, action, tenant, res, reqID string) {
	_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: action, TenantID: tenant, Resource: res, Result: audit.ResultAllow, RequestID: reqID})
}
