// Package ledger 实现风险台账与整改闭环（FR-LGR-001~009，DR-02，一票否决③⑤）。
// 状态机四态：待整改 open / 整改中 doing / 已闭环 closed / 待通报 notify（C-6 与 demo 口径一致）。
// closed 只能经复测验证（Verify）达成——整改闭环率不可造假（AX-4）。
package ledger

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

const (
	StatusOpen   = "open"
	StatusDoing  = "doing"
	StatusClosed = "closed"
	StatusNotify = "notify"
)

var (
	ErrInvalid   = errors.New("ledger: invalid item")
	ErrState     = errors.New("ledger: illegal state transition")
	ErrNoVerf    = errors.New("ledger: verifier not configured（复测器未接入，禁止置已闭环）")
	ErrNotFound  = errors.New("ledger: not found")
	ErrDuplicate = errors.New("ledger: duplicate id")

	phases   = map[string]bool{"P1": true, "P2": true, "P3": true, "P4": true, "P5": true}
	cats     = map[string]bool{"系统架构类": true, "代码密码类": true, "业务经营类": true}
	levels   = map[string]bool{"严重": true, "高": true, "中": true}
	statuses = map[string]bool{StatusOpen: true, StatusDoing: true, StatusClosed: true, StatusNotify: true}
	// 处置措施矩阵（FR-LGR-003，7 类；deadline 供前端提示）
	Actions = map[string]string{
		"删除": "即时", "联系平台依法依规清理": "1–3 工作日", "访问控制": "即时",
		"脱敏处理": "1–5 工作日", "迁移防护": "1–2 周", "安全加固": "持续", "制度完善": "1 个月",
	}
)

type Item struct {
	ID       string    `json:"id"`
	Tenant   string    `json:"tenant"`
	Phase    string    `json:"phase"`
	Category string    `json:"cat"`
	Asset    string    `json:"asset"`
	Title    string    `json:"title"`
	Level    string    `json:"lv"`
	Source   string    `json:"src"`
	Found    time.Time `json:"date"`
	Action   string    `json:"action"`
	Owner    string    `json:"owner"`
	Due      time.Time `json:"due"`
	Status   string    `json:"st"`
	Notify   bool      `json:"notify"`
	Note     string    `json:"note,omitempty"` // 复测记录
	// XChk 独立信源清单（V-5 零误报门1 / AX-3：规则ID、工具通道、人工复核编号等）。
	// 「严重」级结论必须有两个以上独立**通道**支撑（同一次判定轮的多规则、evidence:none
	// 均不算）；单源证据入账时降级为「高」并留痕。
	XChk []string `json:"xchk,omitempty"`
	// Refute 反证记录（V-10 零误报门2 / AX-3：强制回答「哪些事实能否定它」）。
	// 「严重」级必须至少有一条已回答的反证（Outcome 非空）：没做过反证不得给最高级；
	// 反证成立（confirmed）= 结论被否定，降级为「中」并留痕待核查。
	Refute []RefuteCheck `json:"refute,omitempty"`
	// Verifs 复测/验证记录（S-2 零误报门3 / AX-3+AX-4：闭环必须可验证）。
	// 每次 Verify 追加一条：方法（sandbox/manual/cross_tool）、结果、证据引用、操作人。
	// 「已闭环」的唯一合法路径=最近一条验证为 reproduced 且带证据引用（C-5）。
	Verifs []Verification `json:"verifs,omitempty"`
}

// 验证方法（S-2）：sandbox=沙箱 PoC 复现（ENH-10 provider，未接入即 501）；
// manual=人工复测（人在环，MVP 可用形态）；cross_tool=跨工具交叉验证（门1 的复测面）。
const (
	MethodSandbox   = "sandbox"
	MethodManual    = "manual"
	MethodCrossTool = "cross_tool"
)

// 验证结果（S-2）：reproduced=复现成功（可闭环）；refuted=复现失败/被否定；
// inconclusive=无法判定（回退整改中，不得闭环）。
const (
	ResultReproduced   = "reproduced"
	ResultRefuted      = "refuted"
	ResultInconclusive = "inconclusive"
)

// Verification 一条验证记录（S-2 / 门3）。EvidenceRef 对 reproduced 强制（C-5）：
// 无证据引用的「复现成功」=不可回溯的主张，不是闭环依据。
type Verification struct {
	Method      string    `json:"method"`
	Result      string    `json:"result"`
	Verifier    string    `json:"verifier"` // 操作人/提供者（provider 名或用户 ID）
	EvidenceRef string    `json:"evidence_ref,omitempty"`
	TS          time.Time `json:"ts"`
	Note        string    `json:"note,omitempty"`
}

// Validate 验证记录自检（方法/结果枚举 + reproduced 必须有证据引用）。
func (v Verification) Validate() error {
	switch v.Method {
	case MethodSandbox, MethodManual, MethodCrossTool:
	default:
		return fmt.Errorf("ledger: 非法验证方法 %q（须 sandbox|manual|cross_tool）", v.Method)
	}
	switch v.Result {
	case ResultReproduced, ResultRefuted, ResultInconclusive:
	default:
		return fmt.Errorf("ledger: 非法验证结果 %q", v.Result)
	}
	if v.Result == ResultReproduced && strings.TrimSpace(v.EvidenceRef) == "" {
		return errors.New("ledger: reproduced 必须带证据引用（evidence_ref；C-5 无可回溯主张不得闭环）")
	}
	return nil
}

// RefuteCheck 一条反证记录（门2）：可否定结论的事实 + 核查结果 + 依据。
// Outcome 取值：excluded=已排除（结论成立）/ confirmed=反证成立（结论应降级）。
type RefuteCheck struct {
	Claim    string `json:"claim"`              // 可否定本结论的事实（如「命中值为示例占位符」）
	Outcome  string `json:"outcome"`            // excluded|confirmed（空=未回答=未做反证）
	Evidence string `json:"evidence,omitempty"` // 依据（规则ID/文件路径模式/资产状态/证据ref）
}

func (i Item) Validate() error {
	var bad []string
	if strings.TrimSpace(i.ID) == "" {
		bad = append(bad, "id")
	}
	if strings.TrimSpace(i.Tenant) == "" {
		bad = append(bad, "tenant")
	}
	if !phases[i.Phase] {
		bad = append(bad, "phase")
	}
	if !cats[i.Category] {
		bad = append(bad, "category")
	}
	if strings.TrimSpace(i.Title) == "" {
		bad = append(bad, "title")
	}
	if !levels[i.Level] {
		bad = append(bad, "level")
	}
	if strings.TrimSpace(i.Source) == "" {
		bad = append(bad, "source")
	}
	if strings.TrimSpace(i.Action) == "" {
		bad = append(bad, "action")
	}
	if i.Action != "" {
		if _, known := Actions[i.Action]; !known {
			bad = append(bad, "action:"+i.Action)
		} // 非7类措施（组合措施前缀校验在 M1 完善）
	}
	if strings.TrimSpace(i.Owner) == "" {
		bad = append(bad, "owner")
	}
	if i.Due.IsZero() {
		bad = append(bad, "due")
	}
	if i.Found.IsZero() {
		bad = append(bad, "found")
	}
	if i.Status != "" && !statuses[i.Status] {
		bad = append(bad, "status")
	}
	if len(bad) > 0 {
		return fmt.Errorf("%w: 缺失/非法 %s", ErrInvalid, strings.Join(bad, ","))
	}
	return nil
}

type Filter struct {
	Status string
	Phase  string
	Cat    string
	Tenant string
}

type Store interface {
	Create(ctx context.Context, i Item) error
	Get(ctx context.Context, id string) (Item, error)
	Update(ctx context.Context, i Item) error
	List(ctx context.Context) ([]Item, error)
}

type MemStore struct {
	mu sync.RWMutex
	m  map[string]Item
}

func NewMemStore() *MemStore { return &MemStore{m: map[string]Item{}} }

func (s *MemStore) Create(_ context.Context, i Item) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[i.ID]; ok {
		return ErrDuplicate
	}
	s.m[i.ID] = i
	return nil
}

func (s *MemStore) Get(_ context.Context, id string) (Item, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	i, ok := s.m[id]
	if !ok {
		return Item{}, ErrNotFound
	}
	return i, nil
}

func (s *MemStore) Update(_ context.Context, i Item) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[i.ID] = i
	return nil
}

func (s *MemStore) List(_ context.Context) ([]Item, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Item, 0, len(s.m))
	for _, i := range s.m {
		out = append(out, i)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, nil
}

// Verifier 复测钩子（FR-LGR-005）：MVP 由注入实现（如重跑对应阶段排查）；
// 工具接入后由五阶段工作流的差分复扫承担。
// Verifier 验证提供者端口（S-2）：ENH-10 沙箱 PoC 提供者实现本端口。
// 契约（前置条件，见开发计划 §15.7）：隔离微 VM 池 + 回连确认（interactsh）+
// 非破坏性且可关闭（NFR-SEC-010）+ 产物入证据 WORM + 高危动作人工审批（AX-5）。
// 未接入时 method=sandbox 的验证返回 ErrNoVerf（501）——不拿「没有沙箱」冒充闭环。
type Verifier func(ctx context.Context, i Item) (Verification, error)
type Service struct {
	store Store
	log   audit.Log
	ver   Verifier
	now   func() time.Time
}

func NewService(store Store, log audit.Log) *Service {
	return &Service{store: store, log: log, now: time.Now}
}

func (s *Service) SetVerifier(v Verifier) { s.ver = v }

func (s *Service) Create(ctx context.Context, p rbac.Principal, reqID string, i Item) error {
	if !p.Can(rbac.PermWriteAssets) {
		s.deny(ctx, p, "ledger.create", i.Tenant, i.ID, reqID)
		return rbac.ErrForbidden
	}
	if !p.InScope(i.Tenant) {
		s.deny(ctx, p, "ledger.create", i.Tenant, i.ID, reqID)
		return rbac.ErrCrossTenant
	}
	if i.Status == "" {
		i.Status = StatusOpen
	}
	if i.Status == StatusClosed {
		return fmt.Errorf("%w: 入账不得直接置已闭环（须经复测）", ErrState)
	}
	if err := i.Validate(); err != nil {
		return err
	}
	// V-5 零误报门1（交叉去噪）最小实现 / AX-3 + 设计方案 §7.1 门1：
	// 「严重」级结论必须有两个以上独立信源（xchk）支撑，否则降级为「高」并在 Note 留痕。
	// 为什么在 Create 而不在各采集器：所有入账路径（sweep/collect/darkweb/REST 手工建账）
	// 共用同一闸门，旁路任一路径都无法产出「无交叉验证的严重级」——一票否决⑨的工程落点。
	// 语义选择=降级而非拒绝：单源命中仍是真实发现（拒账=丢事实），但不得标「严重」
	// （不可复现/未交叉验证不得给最高级=零误报链第一道门）。
	if i.Level == "严重" && distinctSources(i.XChk) < 2 {
		i.Level = "高"
		i.Note = appendNote(i.Note, "门1未过：严重级独立信源不足（<2），降级为高并留痕（零误报门1/AX-3）")
		s.allow(ctx, p, "ledger.gate1_downgrade", i.Tenant, i.ID, reqID)
	}
	// V-10 零误报门2（反证搜索 / AX-3 / 设计方案 §7.1 门2）：确定性最小实现=
	// 「严重」级必须已对「哪些事实能否定它」做出回答（Refute.Outcome 非空）。
	// - 一条都没回答 → 降级为「高」（没做过反证不得给最高级）
	// - 反证成立（任一 confirmed）→ 降级为「中」并留痕（结论被否定，待核查）
	// 与门1 同址执行：所有入账路径（sweep/collect/darkweb/REST）共用，旁路无门。
	if i.Level == "严重" {
		switch refuteVerdict(i.Refute) {
		case refuteNone:
			i.Level = "高"
			i.Note = appendNote(i.Note, "门2未过：无已回答反证（未做反证搜索），降级为高并留痕（零误报门2/AX-3）")
			s.allow(ctx, p, "ledger.gate2_downgrade", i.Tenant, i.ID, reqID)
		case refuteConfirmed:
			i.Level = "中"
			i.Note = appendNote(i.Note, "门2未过：反证成立（结论被否定），降级为中并留痕待核查（零误报门2/AX-3）")
			s.allow(ctx, p, "ledger.gate2_downgrade", i.Tenant, i.ID, reqID)
		}
	}
	if err := s.store.Create(ctx, i); err != nil {
		return err
	}
	s.allow(ctx, p, "ledger.create", i.Tenant, i.ID, reqID)
	return nil
}

// distinctSources 独立信源**通道**数（同一通道的多个标注不构成交叉验证）：
// 一次判定轮的 rule:A/rule:B 同属检测引擎通道=自证，不是两个独立信源；
// evidence:none 是「无锚点」诚实占位，不计源；不同 tool 视为独立通道（跨工具交叉）。
func distinctSources(xs []string) int {
	seen := map[string]bool{}
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		ch, val := x, x
		if i := strings.IndexByte(x, ':'); i >= 0 {
			ch, val = strings.ToLower(strings.TrimSpace(x[:i])), strings.TrimSpace(x[i+1:])
		}
		switch ch {
		case "rule":
			seen["rule"] = true // 同一检测引擎的多条规则=同一信源
		case "tool":
			if val == "" {
				continue
			}
			seen["tool:"+strings.ToLower(val)] = true // 同工具重复不计数，跨工具才算独立
		case "evidence":
			if val == "" || strings.EqualFold(val, "none") {
				continue // 无证据锚点不得充当第二信源
			}
			seen["evidence"] = true
		default:
			seen[ch] = true
		}
	}
	return len(seen)
}

// noteSuffix 验证备注拼接到台账 Note（记录本身已存于 Verifs，此处供列表视图直读）。
func noteSuffix(note string) string {
	if strings.TrimSpace(note) == "" {
		return ""
	}
	return "：" + note
}

// appendNote 追加留痕（分号分隔；不覆盖既有内容=复测记录与门1 降级原因并存）。
func appendNote(note, add string) string {
	if strings.TrimSpace(note) == "" {
		return add
	}
	return note + "；" + add
}

// 反证裁决（V-10 门2）：none=无已回答反证 / confirmed=反证成立 / excluded=已排除。
const (
	refuteNone      = "none"
	refuteConfirmed = "confirmed"
	refuteExcluded  = "excluded"
)

// refuteVerdict 汇总反证记录：confirmed 优先（任一成立即结论被否定，其余不计）；
// 无已回答（Outcome 空）的记录视为「未做反证」，不构成已排除。
func refuteVerdict(rs []RefuteCheck) string {
	answered := 0
	for _, r := range rs {
		switch strings.TrimSpace(r.Outcome) {
		case "confirmed":
			return refuteConfirmed
		case "excluded":
			answered++
		}
	}
	if answered == 0 {
		return refuteNone
	}
	return refuteExcluded
}

func (s *Service) Get(ctx context.Context, p rbac.Principal, reqID, id string) (Item, error) {
	i, err := s.store.Get(ctx, id)
	if err != nil {
		return Item{}, err
	}
	if !p.InScope(i.Tenant) {
		s.deny(ctx, p, "ledger.read", i.Tenant, id, reqID)
		return Item{}, rbac.ErrCrossTenant
	}
	return i, nil
}

// SetStatus 受控状态迁移：closed 只能经 Verify；open→doing；doing→notify；notify→doing。
func (s *Service) SetStatus(ctx context.Context, p rbac.Principal, reqID, id, to string) error {
	i, err := s.Get(ctx, p, reqID, id)
	if err != nil {
		return err
	}
	allowed := map[string][]string{
		StatusOpen:   {StatusDoing},
		StatusDoing:  {StatusNotify},
		StatusNotify: {StatusDoing},
	}
	if to == StatusClosed {
		return fmt.Errorf("%w: 请使用复测(Verify)闭环", ErrState)
	}
	ok := false
	for _, t := range allowed[i.Status] {
		if t == to {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("%w: %s→%s", ErrState, i.Status, to)
	}
	i.Status = to
	if err := s.store.Update(ctx, i); err != nil {
		return err
	}
	s.allow(ctx, p, "ledger.status", i.Tenant, id, reqID)
	return nil
}

// Verify 复测/验证（FR-LGR-005 + S-2 门3）：记录一条验证，按结果迁移状态。
//
//	reproduced           → 已闭环（closed；唯一合法路径）
//	refuted/inconclusive → 回退整改中（doing；不可闭环）
//
// 校验失败（非法方法/结果、reproduced 无证据引用）→ ErrInvalid（400），不留半记录。
// method=sandbox 且未接入 provider → ErrNoVerf（501）：不拿「没有沙箱」冒充闭环。
func (s *Service) Verify(ctx context.Context, p rbac.Principal, reqID, id string, v Verification) (Verification, error) {
	i, err := s.Get(ctx, p, reqID, id)
	if err != nil {
		return Verification{}, err
	}
	if v.Method == MethodSandbox {
		if s.ver == nil {
			s.deny(ctx, p, "ledger.verify", i.Tenant, id, reqID)
			return Verification{}, ErrNoVerf
		}
		rec, err := s.ver(ctx, i) // provider 权威：调用方声明的方法/结果以 provider 产出为准
		if err != nil {
			return Verification{}, err
		}
		v = rec
	}
	if err := v.Validate(); err != nil {
		s.deny(ctx, p, "ledger.verify", i.Tenant, id, reqID)
		return Verification{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if v.TS.IsZero() {
		v.TS = s.now().UTC()
	}
	if v.Verifier == "" {
		v.Verifier = p.UserID
	}
	i.Verifs = append(i.Verifs, v)
	switch v.Result {
	case ResultReproduced:
		i.Status = StatusClosed
		i.Note = appendNote(i.Note, "门3通过："+v.Method+" 复现成功（证据 "+v.EvidenceRef+"）"+noteSuffix(v.Note))
	case ResultRefuted:
		i.Status = StatusDoing
		i.Note = appendNote(i.Note, "门3未过：复现失败/被否定（"+v.Method+"）"+noteSuffix(v.Note))
	default: // inconclusive
		i.Status = StatusDoing
		i.Note = appendNote(i.Note, "门3未过：无法判定（"+v.Method+"），回退整改中"+noteSuffix(v.Note))
	}
	if err := s.store.Update(ctx, i); err != nil {
		return v, err
	}
	s.allow(ctx, p, "ledger.verify", i.Tenant, id, reqID)
	return v, nil
}

// MarkNotify 置「待通报」并生成通报标记（FR-LGR-007 的 MVP 子集；报送渠道为 G8-02）。
func (s *Service) MarkNotify(ctx context.Context, p rbac.Principal, reqID, id string) error {
	i, err := s.Get(ctx, p, reqID, id)
	if err != nil {
		return err
	}
	i.Status = StatusNotify
	i.Notify = true
	if err := s.store.Update(ctx, i); err != nil {
		return err
	}
	s.allow(ctx, p, "ledger.notify", i.Tenant, id, reqID)
	return nil
}

func (s *Service) List(ctx context.Context, p rbac.Principal, reqID string, f Filter) ([]Item, error) {
	all, err := s.store.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Item, 0, len(all))
	for _, i := range all {
		if !p.InScope(i.Tenant) {
			continue
		}
		if f.Status != "" && i.Status != f.Status {
			continue
		}
		if f.Phase != "" && i.Phase != f.Phase {
			continue
		}
		if f.Cat != "" && i.Category != f.Cat {
			continue
		}
		if f.Tenant != "" && i.Tenant != f.Tenant {
			continue
		}
		out = append(out, i)
	}
	return out, nil
}

// Counts 四态计数（FR-LGR-002 验收：计数与筛选结果完全一致）。
func (s *Service) Counts(ctx context.Context, p rbac.Principal) map[string]int {
	c := map[string]int{"total": 0, StatusOpen: 0, StatusDoing: 0, StatusClosed: 0, StatusNotify: 0}
	all, _ := s.store.List(ctx)
	for _, i := range all {
		if p.InScope(i.Tenant) {
			c["total"]++
			c[i.Status]++
		}
	}
	return c
}

// NearDue 临期（due 在 now..now+within，且未闭环）。
func (s *Service) NearDue(ctx context.Context, p rbac.Principal, within time.Duration) []Item {
	now := s.now()
	all, _ := s.store.List(ctx)
	var out []Item
	for _, i := range all {
		if !p.InScope(i.Tenant) || i.Status == StatusClosed {
			continue
		}
		if i.Due.After(now) && i.Due.Before(now.Add(within)) {
			out = append(out, i)
		}
	}
	return out
}

// Overdue 逾期未整改。
func (s *Service) Overdue(ctx context.Context, p rbac.Principal) []Item {
	now := s.now()
	all, _ := s.store.List(ctx)
	var out []Item
	for _, i := range all {
		if !p.InScope(i.Tenant) || i.Status == StatusClosed {
			continue
		}
		if i.Due.Before(now) {
			out = append(out, i)
		}
	}
	return out
}

func (s *Service) deny(ctx context.Context, p rbac.Principal, action, tenant, res, reqID string) {
	_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: action, TenantID: tenant, Resource: res, Result: audit.ResultDeny, RequestID: reqID})
}

func (s *Service) allow(ctx context.Context, p rbac.Principal, action, tenant, res, reqID string) {
	_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: action, TenantID: tenant, Resource: res, Result: audit.ResultAllow, RequestID: reqID})
}
