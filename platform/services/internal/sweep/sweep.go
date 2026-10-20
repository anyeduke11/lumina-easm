// Package sweep 实现五阶段排查工作流（FR-DSC-001~005 / F2 / DR-03）。
// MVP 编排：进程内按 P1→P5 顺序执行 + (tenant,asset,rule) 幂等去重键，
// 作为 Temporal 断点续跑（ENH-01）的近似；每阶段做真实确定性判定——
// 调用 classify 引擎核查租户资产（AX-2：发现类工作交由工具链属 ENH-08，此处承接判定与入账）。
package sweep

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/authz"
	"github.com/wangdev88/easm-platform/platform/services/internal/classify"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// Phase 阶段模型（DR-03；步骤数 4/4/5/3/4 为一票否决①验收口径）。
type Phase struct {
	ID       string
	Name     string
	Tag      string
	Goal     string
	Carriers []string
	Scope    string
	Steps    []Step
	Risks    []string
	Outputs  []string
	SubCodes []string
}

type Step struct {
	N   string
	D   string
	Out string
}

// refuteOutcome 资产状态反证裁决（V-10 门2，确定性）：在用=反证已排除；
// 其余（闲置/停用/废弃/未知）=反证成立（命中可能只是历史残留）。
func refuteOutcome(status string) string {
	if status == "" || status == "在用" {
		return "excluded"
	}
	return "confirmed"
}

func Phases() []Phase {
	return []Phase{
		{ID: "P1", Name: "搜索引擎基础域名资产排查", Tag: "基础信息摸排",
			Goal:     "以标准全称、简称为核心基础信息，依托主流搜索引擎高级语法开展精准检索，初步归集公开域名、关联站点、公开页面及附件资源，完成基础网络资产摸排",
			Carriers: []string{"百度", "搜狗", "必应"},
			Scope:    "公开域名、关联站点、公开页面及附件资源",
			Steps: []Step{
				{N: "基础域名归集", D: "全称/简称检索归集主域名与子域，甄别第三方同名站点", Out: "基础域名清单"},
				{N: "公开附件排查", D: "检索涉单位公开附件并逐项核查内容", Out: "附件清单+内容核查记录"},
				{N: "风险页面核查", D: "遍历归集域名公开页面，核查后台/测试/临时页面", Out: "风险页面清单"},
				{N: "页面内容核查", D: "核查内网 IP、服务器地址、隐私与业务规则外露", Out: "内容泄露明细"},
			},
			Risks:    []string{"网页违规泄露内网地址/服务器信息/后台登录入口", "公开附件留存商业秘密与人员隐私", "测试/临时页面长期留存"},
			Outputs:  []string{"基础域名清单", "公开附件清单", "风险页面清单", "页面内容泄露明细"},
			SubCodes: []string{"STR-1", "STR-2", "STR-3", "STR-4", "STR-5"},
		},
		{ID: "P2", Name: "空间测绘平台全域资产摸排及台账建档", Tag: "全域资产归集",
			Goal:     "突破通用搜索引擎局限，深度挖掘隐蔽、闲置、未备案的外网资产，摸清底数并统一归集建档",
			Carriers: []string{"Fofa", "Quake", "Hunter（鹰图）", "crt.sh"},
			Scope:    "全域外网资产与证书透明日志",
			Steps: []Step{
				{N: "全域资产搜集", D: "四平台并行查询主体关联资产", Out: "全域资产原始清单"},
				{N: "资产核验去重", D: "归属判定 + 跨源去重归并", Out: "核验资产清单"},
				{N: "证书盲区摸排", D: "通配符反查 + SAN 展开 + DNS/HTTP 交叉验证", Out: "证书派生清单"},
				{N: "资产汇总建档", D: "台账字段自动补全并建档", Out: "全量资产台账"},
			},
			Risks:    []string{"未备案隐蔽子域名", "废弃系统/设备管理后台公网暴露", "过度公示设备参数与版本", "闲置资产留存敏感数据"},
			Outputs:  []string{"互联网全量资产清单", "隐蔽子域名清单", "证书派生清单"},
			SubCodes: []string{"MAP-1", "MAP-2", "MAP-3", "MAP-4"},
		},
		{ID: "P3", Name: "端口目录扫描及增量资产、敏感数据深度排查", Tag: "深度深挖核查",
			Goal:     "以已建档资产为基础，通过专业扫描工具开展端口、目录深度探测，挖掘隐蔽增量资产并核查敏感暴露",
			Carriers: []string{"Nmap", "Dirsearch", "御剑"},
			Scope:    "已建档全量资产的端口/目录/文件层",
			Steps: []Step{
				{N: "全域端口扫描", D: "授权范围端口探测（速率窗口合规）", Out: "端口服务清单"},
				{N: "目录爆破探测", D: "按技术栈动态字典爆破目录路径", Out: "目录路径清单"},
				{N: "敏感文件筛查", D: "内容指纹识别备份/配置/源码包", Out: "敏感文件清单"},
				{N: "增量资产挖掘", D: "新发现资产指纹合并入账", Out: "增量资产清单"},
				{N: "应用信息复核", D: "页面/服务指纹/截图复核", Out: "应用信息复核表"},
			},
			Risks:    []string{"高危端口公网开放", "后台/隐藏目录匿名可访问", "备份/源码包可下载", "配置文件泄露凭据与路径"},
			Outputs:  []string{"端口服务清单", "目录路径清单", "敏感文件清单", "增量资产清单"},
			SubCodes: []string{"SCAN-1", "SCAN-2", "SCAN-3", "SCAN-4", "SCAN-5"},
		},
		{ID: "P4", Name: "第三方多渠道涉相关单位敏感数据专项排查", Tag: "外部边界延伸",
			Goal:     "向外延伸排查边界，全覆盖代码仓库、文档网盘与社交平台，核查核心技术资料与敏感数据违规公开",
			Carriers: []string{"GitHub/Gitee/GitLab", "百度文库/豆丁网/道客巴巴/公开网盘", "微信公众号/微博/行业社群"},
			Scope:    "第三方公开渠道",
			Steps: []Step{
				{N: "开源代码仓库平台排查", D: "关键词扩展检索 + 密钥有效性验证 + 历史提交回溯", Out: "代码仓库泄露清单"},
				{N: "文档及网盘平台排查", D: "文档 OCR 解析 + 过度披露核查", Out: "文档网盘泄露清单"},
				{N: "社交自媒体平台排查", D: "内部动态/人员隐私 NER 识别", Out: "社交渠道泄露清单"},
			},
			Risks:    []string{"源码/配置/密钥违规公开", "拓扑与架构方案外泄", "历史提交可回溯", "词条过度披露组织与人员", "社交平台泄露内部动态"},
			Outputs:  []string{"代码仓库泄露清单", "文档网盘泄露清单", "社交渠道泄露清单"},
			SubCodes: []string{"EXT-1", "EXT-2", "EXT-3"},
		},
		{ID: "P5", Name: "暗网论坛涉相关单位泄露信息排查", Tag: "深层风险兜底",
			Goal:     "针对常规渠道无法覆盖的暗网及地下论坛兜底排查，补齐盲区",
			Carriers: []string{"暗网监测渠道", "行业风险情报平台", "地下交易社区", "隐秘分享渠道"},
			Scope:    "暗网与地下渠道（合规渠道）",
			Steps: []Step{
				{N: "暗网检索", D: "情报源常态接入，新增贴文实时入库", Out: "暗网命中记录"},
				{N: "泄露归属确认", D: "资产指纹比对确认归属", Out: "归属确认结论"},
				{N: "泄露规模评估", D: "样本结构+ID 连续性反推量级区间", Out: "影响评估"},
				{N: "流转链路追踪", D: "发布者/收款地址/文案模板聚类 + 线索包固化", Out: "证据链线索包"},
			},
			Risks:    []string{"用户/员工数据公开售卖", "源码/备份/敏感文档倒卖", "运维账号密钥传播", "隐蔽性泄露长期不可见"},
			Outputs:  []string{"暗网命中记录", "归属确认结论", "影响评估", "证据链线索包"},
			SubCodes: []string{"DRK-1", "DRK-2"},
		},
	}
}

func PhaseIDs() []string {
	ph := Phases()
	out := make([]string, 0, len(ph))
	for _, p := range ph {
		out = append(out, p.ID)
	}
	return out
}

// ---- 服务 ----

type AssetLister interface {
	ListByTenant(ctx context.Context, tenantID string) ([]asset.Asset, error)
}

type Detector interface {
	Detect(content string, in classify.Input) []classify.Hit
}

type IssueWriter interface {
	Create(ctx context.Context, p rbac.Principal, reqID string, i ledger.Item) error
	List(ctx context.Context, p rbac.Principal, reqID string, f ledger.Filter) ([]ledger.Item, error)
}

// ScopeChecker 授权闸（authz.Service 满足，FR-DSC-013）：无有效 scope 的租户不得执行排查。
// MVP 的判定轮虽不发包，仍强制同一闸口——保证 ENH-08 工具链接入后无旁路（不靠自觉）。
type ScopeChecker interface {
	Validate(ctx context.Context, tenant string) error
}

// Limiter 授权参数读口（authz.Service.Get 满足）：编排层消费 scope.rate_limit。
// S-1 销账口径：限速的**真实消费点**在 collect 工具层（nmap --max-rate / ffuf -rate）；
// 编排层（sweep）在每个资产的判定轮之间施加同一限速的步间最小间隔——
// 进程内确定性阶段无网络 I/O 时该间隔是「接缝在位但无可调速对象」的显式形态
// （PacedMS=0），工具步骤（ENH-08）接入后同一接缝立即生效，无需改上层。
type Limiter interface {
	Get(ctx context.Context, tenant string) (authz.Scope, bool, error)
}

// paceInterval 令牌桶间隔：rate req/s → 每请求间隔；<=0=不限速。
func paceInterval(rate int) time.Duration {
	if rate <= 0 {
		return 0
	}
	return time.Second / time.Duration(rate)
}

const (
	StatusPending = "pending"
	StatusRunning = "running"
	StatusDone    = "done"
	StatusFailed  = "failed"
)

// ErrUnknownPhase 阶段口径唯一（C-2）：未知阶段码作为 400 类错误上浮。
var ErrUnknownPhase = fmt.Errorf("sweep: unknown phase")

type StepRun struct {
	Phase     string   `json:"phase"`
	Step      string   `json:"step"`
	Status    string   `json:"status"`
	Outputs   []string `json:"outputs,omitempty"`
	NewIssues int      `json:"new_issues"`
}

type Sweep struct {
	ID        string     `json:"id"`
	Tenant    string     `json:"tenant"`
	Phases    []string   `json:"phases"`
	Status    string     `json:"status"`
	Steps     []StepRun  `json:"steps"`
	Findings  int        `json:"findings"`
	Error     string     `json:"error,omitempty"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	// RateLimit 本次执行消费的授权限速（req/s；0=未配置/不限）。
	// S-1 销账：编排层令牌桶消费留痕——授权书写了限速，执行行上要能看见用了多少。
	RateLimit int `json:"rate_limit,omitempty"`
	// PacedMS 本次执行累计的限速等待毫秒（0=未限速或无可调速对象）。
	PacedMS int64 `json:"paced_ms,omitempty"`
}

type Row struct {
	Tenant string    `json:"tenant"`
	Cov    []float64 `json:"cov"`
	Found  []int     `json:"found"`
	Open   []int     `json:"open"`
	Status string    `json:"status"`
}

type Service struct {
	assets AssetLister
	det    Detector
	led    IssueWriter

	mu      sync.Mutex
	cov     map[string]map[string]int // tenant → phase → 已扫资产数
	store   Store                     // nil=内存自持（MVP 默认）；注入后 sweep 行为跨进程事实源
	sweeps  map[string]*Sweep
	seq     int
	itemSeq int
	scope   ScopeChecker
	now     func() time.Time
	// lim 授权参数读口（authz.Service.Get 满足）：消费 scope.rate_limit（S-1 销账）。
	// nil=编排层不限速（生产装配必配，与 collect.WithLimiter 同口径）。
	lim Limiter
	// paceFn 限速等待原语（测试注入记录器；默认定时器）。返回 error 即中止执行。
	paceFn func(ctx context.Context, d time.Duration) error
	// StepHook 每步落盘后回调（默认 nil 零开销）：崩溃注入演练/进度观测点。
	// 返回 error 即中止本次执行——行保留已完成 steps，重试经 ExecuteInto 断点续跑。
	StepHook func(sw *Sweep) error
}

// SetScope 装配层注入授权闸（nil=不校验，仅限单测）。
func (s *Service) SetScope(c ScopeChecker) { s.scope = c }

// WithLimiter 注入授权参数读口（cmd/server 装配 authz.Service；S-1）。
func (s *Service) WithLimiter(l Limiter) { s.lim = l }

// SetStore 注入 sweep 持久层并 hydrate 覆盖度（矩阵跨重启不塌）；
// 热路径以内存 map 为读缓存，每次状态迁移同步写穿 Store。
// seq 仅进程内 ID 计数（ID 含 Unix 秒前缀防跨进程撞号，无需持久）。
func (s *Service) SetStore(st Store) {
	rows, _ := st.List(context.Background(), "")
	s.mu.Lock()
	s.store = st
	// 台账行号续接（端到端实测缺陷：worker 重启后 itemSeq 归零撞 ledger 主键）。
	// 取既有 L-<year>-<9000+n> 的最大 n（行计数在序号空洞场景仍会撞，最大序号才可靠）。
	if items, err := s.led.List(context.Background(), rbac.Principal{Role: "R7", TenantIDs: []string{"*"}}, "hydrate", ledger.Filter{}); err == nil {
		maxSeq := 0
		for _, it := range items {
			if i := strings.LastIndex(it.ID, "-"); i >= 0 {
				if n, e := strconv.Atoi(it.ID[i+1:]); e == nil && n > maxSeq {
					maxSeq = n
				}
			}
		}
		if maxSeq >= 9000 && maxSeq-9000 > s.itemSeq {
			s.itemSeq = maxSeq - 9000
		}
	}
	for _, r := range rows {
		if len(r.ID) >= 4 && r.ID[:4] == "COV-" {
			m := map[string]int{}
			for _, stp := range r.Steps {
				m[stp.Phase] = stp.NewIssues
			}
			s.cov[r.ID[4:]] = m
		}
	}
	s.mu.Unlock()
}

func NewService(assets AssetLister, det Detector, led IssueWriter) *Service {
	return &Service{
		assets: assets, det: det, led: led,
		cov:    map[string]map[string]int{},
		sweeps: map[string]*Sweep{}, now: time.Now,
	}
}

func (s *Service) Execute(ctx context.Context, p rbac.Principal, reqID, tenant string, phaseIDs []string) (*Sweep, error) {
	if !p.Can(rbac.PermWriteAssets) {
		return nil, rbac.ErrForbidden
	}
	if !p.InScope(tenant) {
		return nil, rbac.ErrCrossTenant
	}
	known := map[string]bool{}
	for _, ph := range Phases() {
		known[ph.ID] = true
	}
	if len(phaseIDs) == 0 {
		phaseIDs = PhaseIDs()
	}
	for _, id := range phaseIDs {
		if !known[id] {
			return nil, fmt.Errorf("%w %q", ErrUnknownPhase, id)
		}
	}
	s.mu.Lock()
	s.seq++
	sw := &Sweep{ID: fmt.Sprintf("S-%d-%04d", s.now().Unix(), s.seq), Tenant: tenant, Phases: phaseIDs, Status: StatusRunning, StartedAt: s.now().UTC()}
	s.sweeps[sw.ID] = sw
	err := s.persistLocked(sw)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}

	if err := s.run(ctx, p, sw); err != nil {
		s.mu.Lock()
		sw.Status, sw.Error = StatusFailed, err.Error()
		end := s.now().UTC()
		sw.EndedAt = &end
		_ = s.persistLocked(sw)
		s.mu.Unlock()
		return sw, err
	}
	s.mu.Lock()
	sw.Status = StatusDone
	end := s.now().UTC()
	sw.EndedAt = &end
	if err := s.persistLocked(sw); err != nil {
		s.mu.Unlock()
		return sw, err
	}
	s.mu.Unlock()
	return sw, nil
}

func (s *Service) persistLocked(sw *Sweep) error {
	if s.store == nil {
		return nil
	}
	cp := *sw
	cp.Steps = append([]StepRun(nil), sw.Steps...)
	return s.store.Save(context.Background(), &cp)
}

// persistCovLocked 覆盖度行（每租户一行 COV-<tenant>；steps 复用为 phase→已扫数）。
func (s *Service) persistCovLocked(tenant string) error {
	if s.store == nil {
		return nil
	}
	var stps []StepRun
	for ph, n := range s.cov[tenant] {
		stps = append(stps, StepRun{Phase: ph, NewIssues: n})
	}
	sort.Slice(stps, func(i, j int) bool { return stps[i].Phase < stps[j].Phase })
	return s.store.Save(context.Background(), &Sweep{ID: covRowID(tenant), Tenant: tenant, Status: "snapshot", Steps: stps})
}

// CreateDispatched Temporal 模式的 server 侧入口：只建行（running）并持久，
// 实际执行交由 worker 的 ExecuteInto（异步派发语义；REST 立即可查进度）。
// 要求已注入 Store——内存模式下无跨进程可言，误用即报错（fail loud）。
func (s *Service) CreateDispatched(ctx context.Context, tenant string, phaseIDs []string) (*Sweep, error) {
	if len(phaseIDs) == 0 {
		phaseIDs = PhaseIDs()
	}
	if err := s.checkPhases(phaseIDs); err != nil {
		return nil, err
	}
	s.mu.Lock()
	st := s.store
	s.mu.Unlock()
	if st == nil {
		return nil, fmt.Errorf("sweep: CreateDispatched 需要注入 Store（Temporal 模式）")
	}
	s.mu.Lock()
	s.seq++
	sw := &Sweep{ID: fmt.Sprintf("S-%d-%04d", s.now().Unix(), s.seq), Tenant: tenant, Phases: phaseIDs, Status: StatusRunning, StartedAt: s.now().UTC()}
	s.sweeps[sw.ID] = sw
	err := s.persistLocked(sw)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return sw, nil
}

func (s *Service) checkPhases(phaseIDs []string) error {
	known := map[string]bool{}
	for _, ph := range Phases() {
		known[ph.ID] = true
	}
	for _, id := range phaseIDs {
		if !known[id] {
			return fmt.Errorf("%w %q", ErrUnknownPhase, id)
		}
	}
	return nil
}

// ExecuteInto worker 侧唯一入口：按既有行 ID 续跑（steps/findings 续加、进度写穿 Store）。
// 幂等：ledger 去重保证重复 activity 重试不复制发现（Temporal at-least-once 语义下的安全网）。
func (s *Service) ExecuteInto(ctx context.Context, p rbac.Principal, reqID, id string) (*Sweep, error) {
	if !p.Can(rbac.PermWriteAssets) {
		return nil, rbac.ErrForbidden
	}
	sw, ok := s.Get(id)
	if !ok || len(sw.ID) >= 4 && sw.ID[:4] == "COV-" {
		return nil, fmt.Errorf("sweep: 行 %q 不可执行", id)
	}
	if sw.Status == StatusDone {
		return &sw, nil // 重放保护：已完成行不重跑
	}
	sp := &sw
	s.mu.Lock()
	s.sweeps[sw.ID] = sp
	s.mu.Unlock()
	if err := s.run(ctx, p, sp); err != nil {
		s.mu.Lock()
		sp.Status, sp.Error = StatusFailed, err.Error()
		end := s.now().UTC()
		sp.EndedAt = &end
		_ = s.persistLocked(sp)
		s.mu.Unlock()
		return sp, err
	}
	s.mu.Lock()
	sp.Status = StatusDone
	end := s.now().UTC()
	sp.EndedAt = &end
	err := s.persistLocked(sp)
	s.mu.Unlock()
	if err != nil {
		return sp, err
	}
	return sp, nil
}

func (s *Service) run(ctx context.Context, p rbac.Principal, sw *Sweep) error {
	if s.scope != nil { // 授权闸：无有效 scope 拒绝执行（FR-DSC-013 / 一票否决⑥）
		if err := s.scope.Validate(ctx, sw.Tenant); err != nil {
			return err
		}
	}
	byID := map[string]Phase{}
	for _, ph := range Phases() {
		byID[ph.ID] = ph
	}
	assets, err := s.assets.ListByTenant(ctx, sw.Tenant)
	if err != nil {
		return err
	}
	existing := s.existingKeys(ctx, sw.Tenant) // 去重以台账为准，一次性装载
	// S-1：解析授权限速一次（每次执行读一次 scope；读失败上浮=不得假装没限速）
	interval := time.Duration(0)
	if s.lim != nil {
		sc, ok, err := s.lim.Get(ctx, sw.Tenant)
		if err != nil {
			return err
		}
		if ok {
			sw.RateLimit = sc.RateLimit
			interval = paceInterval(sc.RateLimit)
		}
	}
	// 断点续跑（NFR-AVL-003）：行内已完成的阶段不重跑（Temporal 重试/崩溃恢复语义）
	donePhases := map[string]bool{}
	for _, stp := range sw.Steps {
		donePhases[stp.Phase] = true
	}
	for _, pid := range sw.Phases { // 顺序执行（P1→P5 依赖序，FR-DSC-003）
		if donePhases[pid] {
			continue
		}
		ph := byID[pid]
		for _, st := range ph.Steps {
			// MVP 每步骤一次判定轮：真实工作 = classify 核查资产（ENH-08 工具链接入后替换为采集+判定）
			stepNew := 0
			for _, a := range assets {
				// S-1：资产判定轮之间施加步间最小间隔（令牌桶消费；interval=0 时零开销）
				if interval > 0 {
					w, err := s.pace(ctx, interval)
					if err != nil {
						return err
					}
					s.mu.Lock()
					sw.PacedMS += w // per-run 累计：等待只归属本执行行
					s.mu.Unlock()
				}
				hits := s.det.Detect(strings.Join([]string{a.Name, a.IP, a.Biz, a.TypeLabel, a.Source}, " "), classify.Input{
					URL: a.Name, Ports: a.Ports, Tech: a.Tech, Title: a.Name,
				})
				n, err := s.fileHits(ctx, p, a, pid, hits, existing)
				if err != nil {
					return err
				}
				stepNew += n
			}
			s.mu.Lock()
			sw.Steps = append(sw.Steps, StepRun{Phase: ph.ID, Step: st.N, Status: "done", Outputs: []string{st.Out}, NewIssues: stepNew})
			sw.Findings += stepNew // 每步只累计本步新增（修复双重计数）
			err = s.persistLocked(sw)
			hook := s.StepHook
			cp := *sw
			s.mu.Unlock()
			if err != nil {
				return err
			}
			if hook != nil {
				if err := hook(&cp); err != nil {
					return err
				}
			}
		}
		s.mu.Lock()
		if s.cov[sw.Tenant] == nil {
			s.cov[sw.Tenant] = map[string]int{}
		}
		if len(assets) > 0 {
			s.cov[sw.Tenant][ph.ID] = len(assets) // 覆盖度 = 已扫/总资产
		}
		err = s.persistCovLocked(sw.Tenant)
		s.mu.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

// existingKeys 从台账反推去重集（账本=唯一事实源；进程重启/内存丢失不复制条目）。
// 键口径：asset + 规则号（Source 尾段以正则 R-[A-Z]+ 提取，不依赖分隔符字节）。
var rxRule = regexp.MustCompile(`R-[A-Z]+$`)

func (s *Service) existingKeys(ctx context.Context, tenant string) map[string]bool {
	items, err := s.led.List(ctx, rbac.Principal{Role: "R7", TenantIDs: []string{"*"}}, "sweep-dedup", ledger.Filter{Tenant: tenant})
	out := map[string]bool{}
	if err != nil {
		return out
	}
	for _, it := range items {
		if m := rxRule.FindString(it.Source); m != "" {
			out[it.Asset+"|"+m] = true
		}
	}
	return out
}

// pace 限速等待（S-1）：ctx 取消即返回 error（不得把限速变成不可中断的睡眠）。
// 返回实际等待毫秒，由调用方累加到执行行 PacedMS（per-run 计数：等待归属本次执行，
// 不放 Service 级字段——否则并发/多轮 sweep 会把别行的等待写进本行，污染取证）。
func (s *Service) pace(ctx context.Context, d time.Duration) (int64, error) {
	fn := s.paceFn
	if fn == nil {
		fn = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	start := s.now()
	if err := fn(ctx, d); err != nil {
		return 0, err
	}
	return s.now().Sub(start).Milliseconds(), nil
}

func (s *Service) fileHits(ctx context.Context, p rbac.Principal, a asset.Asset, phase string, hits []classify.Hit, existing map[string]bool) (int, error) {
	// 阶段归属推定：资产来源含 P1–P5 前缀则用之（问题由该阶段发现），否则用执行阶段
	if len(a.Source) >= 2 && a.Source[0] == 'P' && strings.Contains("12345", a.Source[1:2]) {
		phase = a.Source[:2]
	}
	n := 0
	// V-5 零误报门1：同一判定轮的多条规则属**同一 rule 通道**，不构成互证；
	// 单通道命中若申报「严重」，由 ledger.Create 按独立信源通道数降级为「高」并留痕。
	xchk := make([]string, 0, len(hits))
	for _, h := range hits {
		xchk = append(xchk, "rule:"+h.RuleID)
	}
	for _, h := range hits {
		key := a.Name + "|" + h.RuleID
		if existing[key] {
			continue
		}
		existing[key] = true
		s.mu.Lock()
		s.itemSeq++
		id := fmt.Sprintf("L-%d-%04d", s.now().Year(), 9000+s.itemSeq)
		s.mu.Unlock()
		item := ledger.Item{
			ID:     id,
			Tenant: a.Tenant, Phase: phase, Category: h.Category, Asset: a.Name,
			Title: h.RuleName + "：" + h.Snippet, Level: h.Level,
			Source: a.Source + " · " + h.RuleID, Found: s.now().UTC(),
			Action: "安全加固", Owner: a.Owner, Due: s.now().AddDate(0, 0, 7).UTC(),
			XChk: xchk,
			// V-10 门2：确定性反证=资产是否仍在用。停用/废弃资产上的命中，
			// 「该资产已停用」即成立的反证（confirmed→降级）；在用=反证已排除。
			Refute: []ledger.RefuteCheck{{
				Claim:    "命中资产已停用/废弃（结论随资产失效）",
				Outcome:  refuteOutcome(a.Status),
				Evidence: "asset.status=" + a.Status,
			}},
		}
		if err := s.led.Create(ctx, p, "sweep", item); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Coverage 阶段覆盖度 = 已扫资产 / 租户总资产（无资产为 0，不虚报）。
func (s *Service) Coverage(tenant, phase string) (float64, error) {
	s.mu.Lock()
	done := s.cov[tenant][phase]
	s.mu.Unlock()
	total, err := s.assetCount(tenant)
	if err != nil || total == 0 {
		return 0, err
	}
	return float64(done) / float64(total), nil
}

func (s *Service) assetCount(tenant string) (int, error) {
	// 同步计数缓存：Execute 时已拿过列表；这里以 cov 分母缓存简化——用 sweeps 记录不可靠，直接询问 AssetLister。
	type counter interface {
		Count(context.Context, string) (int, error)
	}
	if c, ok := s.assets.(counter); ok {
		return c.Count(context.Background(), tenant)
	}
	assets, err := s.assets.ListByTenant(context.Background(), tenant)
	if err != nil {
		return 0, err
	}
	return len(assets), nil
}

// Matrix 客户 × 阶段进度（F2.6 / FR-DSC-005）。
func (s *Service) Matrix(tenants []string) []Row {
	ids := PhaseIDs()
	out := make([]Row, 0, len(tenants))
	for _, t := range tenants {
		row := Row{Tenant: t, Cov: make([]float64, 5), Found: make([]int, 5), Open: make([]int, 5)}
		items, _ := s.led.List(context.Background(), rbac.Principal{Role: "R7", TenantIDs: []string{"*"}}, "m", ledger.Filter{Tenant: t})
		for _, it := range items {
			i := idxOf(ids, it.Phase)
			if i < 0 {
				continue
			}
			row.Found[i]++
			if it.Status != ledger.StatusClosed {
				row.Open[i]++
			}
		}
		anyOpen := 0
		for i := range ids {
			row.Cov[i], _ = s.Coverage(t, ids[i])
			anyOpen += row.Open[i]
		}
		switch {
		case anyOpen > 0:
			row.Status = "整改中"
		case row.Cov[0] > 0.99:
			row.Status = "已闭环"
		case row.Cov[0] > 0:
			row.Status = "排查中"
		default:
			row.Status = "待启动"
		}
		out = append(out, row)
	}
	return out
}

func idxOf(hay []string, s string) int {
	for i, v := range hay {
		if v == s {
			return i
		}
	}
	return -1
}

// List/Get 查询（IR-05 /v1/sweeps）：store 注入时以持久行为事实源（跨进程可读，
// Temporal worker 写、server 读），否则内存自持（MVP 单进程）。
func (s *Service) List(tenant string) []Sweep {
	s.mu.Lock()
	st := s.store
	s.mu.Unlock()
	if st != nil {
		rows, _ := st.List(context.Background(), tenant)
		sort.Slice(rows, func(i, j int) bool { return rows[i].ID > rows[j].ID })
		out := rows[:0]
		for _, r := range rows { // 剔除覆盖度快照行（非 sweep）
			if len(r.ID) < 4 || r.ID[:4] != "COV-" {
				out = append(out, r)
			}
		}
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Sweep, 0, len(s.sweeps))
	for _, sw := range s.sweeps {
		if tenant != "" && sw.Tenant != tenant {
			continue
		}
		cp := *sw
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

func (s *Service) Get(id string) (Sweep, bool) {
	s.mu.Lock()
	st := s.store
	s.mu.Unlock()
	if st != nil {
		sw, ok, _ := st.Get(context.Background(), id)
		return sw, ok
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sw, ok := s.sweeps[id]
	if !ok {
		return Sweep{}, false
	}
	return *sw, true
}
