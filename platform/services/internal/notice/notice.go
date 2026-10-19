// Package notice 实现线索通报与合规报送（WP-M2-04 / FR-LGR-007~008、FR-RPT-005、CR-002、A-08）。
// G8-02（真实报送通道与定稿格式）未触达前的**过渡形态**（按清单 §5 M2-04 过渡期条款）：
// 系统侧生成通报单号+材料（通用模板）+ CR-002 三要素留痕（目标/材料哈希/时间戳）+
// A-08 超时显著标识（公安 24h / 省通报中心 48h）；**报送动作=人工投递后回执录入**
// （系统不代签「已报送」，回执号原样留痕）。合规报送总结同理=结构完整可导出，定稿随 G8-02。
package notice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

const (
	TargetPolice = "属地公安机关"
	TargetCenter = "省网络与信息安全通报中心"

	StatusPending   = "待报送"
	StatusSubmitted = "已报送"
)

// deadlines 报送时限（FR-LGR-007：公安 24h / 通报中心 48h）。
var deadlines = map[string]int{TargetPolice: 24, TargetCenter: 48}

var (
	ErrInvalid   = errors.New("notice: 通报请求非法")
	ErrNotFound  = errors.New("notice: 通报不存在")
	ErrDuplicate = errors.New("notice: 该条目已向此目标通报")
	ErrLocked    = errors.New("notice: 通报三要素已锁定（单号/目标/材料哈希不可改写）")
)

// Notice 一次线索通报（CR-002 的记录主体；ID=NB-<sha12(tenant|ledger|target)>=归档键幂等）。
type Notice struct {
	ID           string     `json:"id"`
	Tenant       string     `json:"tenant"`
	LedgerID     string     `json:"ledger_id"`
	Target       string     `json:"target"`
	DeadlineH    int        `json:"deadline_h"`
	Status       string     `json:"status"`
	Material     string     `json:"material,omitempty"` // 通用模板文本（过渡形态；定稿随 G8-02）
	MaterialHash string     `json:"material_hash"`      // CR-002 材料哈希
	MaterialRef  string     `json:"material_ref"`       // 可回溯锚点（证据对象优先，否则行内固化 ref）
	CreatedAt    time.Time  `json:"created_at"`         // CR-002 时间戳
	ReceiptNo    string     `json:"receipt_no,omitempty"`
	SubmittedAt  *time.Time `json:"submitted_at,omitempty"`
	Overdue      bool       `json:"overdue"` // A-08 显著标识（计算字段，非存储态）
}

// DueAt 通报时限界点（自发起时刻起算 24h/48h）。
func (n Notice) DueAt() time.Time { return n.CreatedAt.Add(time.Duration(n.DeadlineH) * time.Hour) }

// isOverdue 未录回执且已过时限=A-08 超时（已报送后义务履行，不再标红）。
func (n Notice) isOverdue(now time.Time) bool {
	return n.Status != StatusSubmitted && now.After(n.DueAt())
}

// Report 合规报送总结（FR-LGR-008 / FR-RPT-005：三段结构+可导出+内容哈希）。
type Report struct {
	Tenant      string    `json:"tenant"`
	GeneratedAt time.Time `json:"generated_at"`
	PeriodFrom  time.Time `json:"period_from,omitempty"`
	PeriodTo    time.Time `json:"period_to,omitempty"`
	ItemCount   int       `json:"item_count"`
	NoticeSent  int       `json:"notice_sent"`
	NoticeOpen  int       `json:"notice_open"`
	Text        string    `json:"text"`
	ContentHash string    `json:"content_hash"`
	EvidenceRef string    `json:"evidence_ref,omitempty"`
}

// LedgerReader 台账读口（ledger.Service 满足）：通报材料取自台账事实，条目不存在即拒。
type LedgerReader interface {
	Get(ctx context.Context, p rbac.Principal, reqID, id string) (ledger.Item, error)
}

// ListAll 全量台账读口（总结统计用；主体作用域由 ledger.Service 内部保证）。
type ListAll interface {
	List(ctx context.Context, p rbac.Principal, reqID string, f ledger.Filter) ([]ledger.Item, error)
}

type Store interface {
	Create(ctx context.Context, n Notice) error
	Get(ctx context.Context, tenant, id string) (Notice, error) // 租户不匹配=ErrNotFound（行级闸）
	Update(ctx context.Context, n Notice) error
	List(ctx context.Context, tenant, status string) ([]Notice, error)
}

type MemStore struct {
	mu sync.RWMutex
	m  map[string]Notice
}

func NewMemStore() *MemStore { return &MemStore{m: map[string]Notice{}} }

func (s *MemStore) Create(_ context.Context, n Notice) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[n.ID]; ok {
		return ErrDuplicate
	}
	s.m[n.ID] = n
	return nil
}

func (s *MemStore) Get(_ context.Context, tenant, id string) (Notice, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.m[id]
	if !ok || n.Tenant != tenant {
		return Notice{}, ErrNotFound
	}
	return n, nil
}

func (s *MemStore) Update(_ context.Context, n Notice) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[n.ID]; !ok || s.m[n.ID].Tenant != n.Tenant {
		return ErrNotFound
	}
	s.m[n.ID] = n
	return nil
}

func (s *MemStore) List(_ context.Context, tenant, status string) ([]Notice, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Notice
	for _, n := range s.m {
		if n.Tenant == tenant && (status == "" || n.Status == status) {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

type Service struct {
	store Store
	log   audit.Log
	led   LedgerReader
	all   ListAll // nil=总结无台账统计面（仅通报计数）
	ev    evidence.Store
	now   func() time.Time
}

func NewService(store Store, log audit.Log, led LedgerReader) *Service {
	return &Service{store: store, log: log, led: led, now: time.Now}
}

// WithLedgerList 注入台账全量读口（总结统计面；ledger.Service 满足）。
func (s *Service) WithLedgerList(l ListAll) { s.all = l }

// WithEvidence 注入证据存储：材料字节固化为不可变对象（C-5；无则行内文本+逻辑 ref）。
func (s *Service) WithEvidence(ev evidence.Store) { s.ev = ev }

// Create 发起线索通报：写权限→InScope(tenant)→目标枚举→台账关联闸（存在+同租户）→
// 渲染通用模板材料→固化（证据优先）→三要素锁定落库+审计。同条目同目标重放=同单号（幂等）。
func (s *Service) Create(ctx context.Context, p rbac.Principal, reqID, tenant, ledgerID, target string) (Notice, error) {
	var zero Notice
	if !p.Can(rbac.PermWriteAssets) {
		s.deny(ctx, p, "notice.create", tenant, reqID)
		return zero, rbac.ErrForbidden
	}
	if !p.InScope(tenant) {
		s.deny(ctx, p, "notice.create", tenant, reqID)
		return zero, rbac.ErrCrossTenant
	}
	dh, ok := deadlines[target]
	if !ok {
		return zero, fmt.Errorf("%w: 通报目标须为 %s|%s", ErrInvalid, TargetPolice, TargetCenter)
	}
	it, err := s.led.Get(ctx, p, reqID, ledgerID)
	if err != nil { // 台账关联闸：不存在=拒（不得以不存在的事向监管报）
		return zero, fmt.Errorf("notice: 台账关联校验失败: %w", err)
	}
	if it.Tenant != tenant {
		return zero, fmt.Errorf("%w: 台账条目属租户 %s（不得以他账向监管报）", ErrInvalid, it.Tenant)
	}
	now := s.now().UTC()
	n := Notice{
		ID: "NB-" + hash12(tenant+"|"+ledgerID+"|"+target), Tenant: tenant, LedgerID: ledgerID,
		Target: target, DeadlineH: dh, Status: StatusPending, CreatedAt: now,
	}
	n.Material = s.renderMaterial(n, it)
	n.MaterialHash = sha256hex([]byte(n.Material))
	n.MaterialRef = "notice://" + tenant + "/" + n.ID
	if s.ev != nil { // 材料字节固化（有证据后端时 ref 指向不可变对象）
		key := "notice/" + tenant + "/" + n.ID + ".md"
		ref, err := s.ev.Put(ctx, key, []byte(n.Material))
		if errors.Is(err, evidence.ErrImmutable) {
			ref = s.ev.RefOf(key)
		} else if err != nil {
			return zero, fmt.Errorf("notice: 通报材料固化失败（不带无锚点材料报送）: %w", err)
		}
		n.MaterialRef = ref
	}
	// 幂等重放：先查同 ID（同条目同目标）——存在即返回既有单（不产第二个归档号）
	if existed, err := s.store.Get(ctx, tenant, n.ID); err == nil {
		s.stamp(&existed, now)
		return existed, nil
	}
	if err := s.store.Create(ctx, n); err != nil {
		return zero, err
	}
	s.allow(ctx, p, "notice.create", tenant, n.ID, reqID)
	s.stamp(&n, now)
	return n, nil
}

// MarkReceipt 录入报送回执（过渡形态的「已报送」唯一合法路径=人工投递后回填）：
// 只追加回执号/时间，单号/目标/材料哈希锁定（CR-002 不可改写）。
func (s *Service) MarkReceipt(ctx context.Context, p rbac.Principal, reqID, tenant, id, receiptNo string, at time.Time) error {
	if !p.Can(rbac.PermWriteAssets) {
		s.deny(ctx, p, "notice.receipt", tenant, reqID)
		return rbac.ErrForbidden
	}
	if !p.InScope(tenant) {
		s.deny(ctx, p, "notice.receipt", tenant, reqID)
		return rbac.ErrCrossTenant
	}
	if strings.TrimSpace(receiptNo) == "" {
		return fmt.Errorf("%w: 回执号必填（无凭证的「已报送」=代签监管动作）", ErrInvalid)
	}
	n, err := s.store.Get(ctx, tenant, id)
	if err != nil {
		return err
	}
	if n.Status == StatusSubmitted { // 首份凭证锁定：报送时间是监管时限判定依据，不可被覆盖
		return fmt.Errorf("%w: 该通报已录回执（重复回填不改写首份凭证）", ErrLocked)
	}
	ts := at.UTC()
	if ts.IsZero() {
		ts = s.now().UTC()
	}
	n.Status, n.ReceiptNo, n.SubmittedAt = StatusSubmitted, receiptNo, &ts
	if err := s.store.Update(ctx, n); err != nil {
		return err
	}
	s.allow(ctx, p, "notice.receipt", tenant, id, reqID)
	return nil
}

// Get 行级租户读单（附超时标识）。
func (s *Service) Get(ctx context.Context, p rbac.Principal, reqID, tenant, id string) (Notice, error) {
	if !p.Can(rbac.PermReadAssets) {
		s.deny(ctx, p, "notice.read", tenant, reqID)
		return Notice{}, rbac.ErrForbidden
	}
	if !p.InScope(tenant) {
		s.deny(ctx, p, "notice.read", tenant, reqID)
		return Notice{}, rbac.ErrCrossTenant
	}
	n, err := s.store.Get(ctx, tenant, id)
	if err != nil {
		return Notice{}, err
	}
	s.stamp(&n, s.now().UTC())
	return n, nil
}

// List 按租户（可选状态筛）列举，逐项附 A-08 超时标识。
func (s *Service) List(ctx context.Context, p rbac.Principal, reqID, tenant, status string) ([]Notice, error) {
	if !p.Can(rbac.PermReadAssets) {
		s.deny(ctx, p, "notice.list", tenant, reqID)
		return nil, rbac.ErrForbidden
	}
	if !p.InScope(tenant) {
		s.deny(ctx, p, "notice.list", tenant, reqID)
		return nil, rbac.ErrCrossTenant
	}
	list, err := s.store.List(ctx, tenant, status)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	for i := range list {
		s.stamp(&list[i], now)
	}
	return list, nil
}

// Overdue 超时未报送清单（A-08 催办面）。
func (s *Service) Overdue(ctx context.Context, p rbac.Principal, reqID, tenant string) ([]Notice, error) {
	list, err := s.List(ctx, p, reqID, tenant, "")
	if err != nil {
		return nil, err
	}
	var out []Notice
	for _, n := range list {
		if n.Overdue {
			out = append(out, n)
		}
	}
	return out, nil
}

// Material 取回通报材料全文（读权限+行级租户闸；固化面可回溯）。
func (s *Service) Material(ctx context.Context, p rbac.Principal, reqID, tenant, id string) (string, error) {
	n, err := s.Get(ctx, p, reqID, tenant, id)
	if err != nil {
		return "", err
	}
	if s.ev != nil && (strings.HasPrefix(n.MaterialRef, "file://") || strings.HasPrefix(n.MaterialRef, "minio://")) {
		if b, err := s.ev.Get(ctx, n.MaterialRef); err == nil && len(b) > 0 {
			return string(b), nil
		} // 证据读失败回退行内文本（材料已入库，不因后端抖动丢报送面）
	}
	return n.Material, nil
}

// Summary 合规报送总结（FR-LGR-008/FR-RPT-005 三段结构；数字取自台账与通报事实=不虚报）。
func (s *Service) Summary(ctx context.Context, p rbac.Principal, reqID, tenant string) (Report, error) {
	var rep Report
	if !p.Can(rbac.PermReadAssets) {
		s.deny(ctx, p, "notice.summary", tenant, reqID)
		return rep, rbac.ErrForbidden
	}
	if !p.InScope(tenant) {
		s.deny(ctx, p, "notice.summary", tenant, reqID)
		return rep, rbac.ErrCrossTenant
	}
	now := s.now().UTC()
	notices, err := s.store.List(ctx, tenant, "")
	if err != nil {
		return rep, err
	}
	sent, open := 0, 0
	for _, n := range notices {
		if n.Status == StatusSubmitted {
			sent++
		} else if n.isOverdue(now) {
			open++
		}
	}
	items := []ledger.Item{}
	if s.all != nil {
		items, err = s.all.List(ctx, p, reqID, ledger.Filter{Tenant: tenant})
		if err != nil {
			return rep, err
		}
	}
	rep = Report{Tenant: tenant, GeneratedAt: now, ItemCount: len(items), NoticeSent: sent, NoticeOpen: open}
	rep.Text = renderSummary(rep, items)
	rep.ContentHash = sha256hex([]byte(rep.Text))
	if s.ev != nil {
		key := "notice/" + tenant + "/summary-" + hash12(rep.ContentHash) + ".md"
		ref, err := s.ev.Put(ctx, key, []byte(rep.Text))
		if errors.Is(err, evidence.ErrImmutable) {
			ref = s.ev.RefOf(key)
		} else if err == nil {
			rep.EvidenceRef = ref
		} // 总结固化失败不阻断导出（文本+哈希已成立；登记降级由调用方按 EvidenceRef 空判）
	}
	s.allow(ctx, p, "notice.summary", tenant, "", reqID)
	return rep, nil
}

// ChainItem 证据链单项：ref + 可独立复核的 sha256/字节数 + 解析状态。
// Resolved=false 时 Error 必非空——「取不到」必须显式带原因进交付包（省略=谎称证据齐备）。
type ChainItem struct {
	Ref      string `json:"ref"`
	Role     string `json:"role"`
	Backend  string `json:"backend,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Bytes    int    `json:"bytes,omitempty"`
	Resolved bool   `json:"resolved"`
	Error    string `json:"error,omitempty"`
}

// Chain 通报交付包（材料 + 逐项证据的可核验清单；FR-CHN-008/C-5 的对外交付面）。
type Chain struct {
	NoticeID    string      `json:"notice_id"`
	Tenant      string      `json:"tenant"`
	LedgerID    string      `json:"ledger_id"`
	Target      string      `json:"target"`
	GeneratedAt time.Time   `json:"generated_at"`
	Items       []ChainItem `json:"items"`
	Verified    int         `json:"verified"`
	Unresolved  int         `json:"unresolved"`
	ContentHash string      `json:"content_hash"`
	Text        string      `json:"text"`
}

// Chain 导出通报证据链：材料 ref（有证据后端=不可变对象，无=通报单行内文本）+
// 台账证据锚点（`note=snapshot_ref=…`，采集/暗网渠道写入的真实格式）逐项解析。
// 读权限+行级租户闸；每项经 evidence.RefInTenant 复核归属（跨租户 ref 不读不纳）。
func (s *Service) Chain(ctx context.Context, p rbac.Principal, reqID, tenant, id string) (Chain, error) {
	var ch Chain
	if !p.Can(rbac.PermReadAssets) {
		s.deny(ctx, p, "notice.chain", tenant, reqID)
		return ch, rbac.ErrForbidden
	}
	if !p.InScope(tenant) { // 与 Get/store 行级过滤同型=纵深冗余（本轮变异如实记录：单独旁路时被下游闸兜住）
		s.deny(ctx, p, "notice.chain", tenant, reqID)
		return ch, rbac.ErrCrossTenant
	}
	n, err := s.Get(ctx, p, reqID, tenant, id)
	if err != nil {
		return ch, err
	}
	ch = Chain{NoticeID: n.ID, Tenant: tenant, LedgerID: n.LedgerID, Target: n.Target, GeneratedAt: s.now().UTC()}
	ch.Items = append(ch.Items, s.resolveRef(ctx, tenant, "通报材料", n.MaterialRef, n.Material))
	if it, err := s.led.Get(ctx, p, reqID, n.LedgerID); err == nil { // 台账已删=材料仍出，锚点项自然缺失（可见的缺失优于伪造）
		for _, ref := range snapshotRefs(it.Note) {
			ch.Items = append(ch.Items, s.resolveRef(ctx, tenant, "台账证据锚点", ref, ""))
		}
	}
	for _, it := range ch.Items {
		if it.Resolved {
			ch.Verified++
		} else {
			ch.Unresolved++
		}
	}
	body, _ := json.Marshal(ch.Items)
	ch.ContentHash = sha256hex(body)
	ch.Text = renderChain(ch, n)
	s.allow(ctx, p, "notice.chain", tenant, id, reqID)
	return ch, nil
}

// resolveRef 解析单个证据 ref：notice://=通报单行内文本（无对象存储时的降级形态，
// 内容仍在库可核）；外部 ref 须经归属校验后向证据后端取字节并计哈希。
func (s *Service) resolveRef(ctx context.Context, tenant, role, ref, inline string) ChainItem {
	it := ChainItem{Ref: ref, Role: role}
	switch {
	case ref == "":
		it.Error = "ref 缺失（该环节未固化证据）"
	case strings.HasPrefix(ref, "notice://"):
		if inline == "" {
			it.Error = "行内材料为空"
			return it
		}
		it.Resolved, it.Backend, it.SHA256, it.Bytes = true, "notice-row", sha256hex([]byte(inline)), len(inline)
	case !evidence.RefInTenant(ref, tenant):
		it.Error = "ref 与租户不匹配（ref_tenant_mismatch，不读取他租户对象）"
	case s.ev == nil:
		it.Error = "证据后端未装配（无法复核字节）"
	default:
		b, err := s.ev.Get(ctx, ref)
		if err != nil {
			it.Error = "证据回溯失败: " + err.Error()
			return it
		}
		it.Resolved, it.Backend, it.SHA256, it.Bytes = true, s.ev.Kind(), sha256hex(b), len(b)
	}
	return it
}

// snapshotRefs 从台账 note 提取 `snapshot_ref=<ref>`（与 collect/darkweb 写入格式对齐；
// 一条 note 只承载一个锚点，故此处返回 0/1 项，但写成切片以免格式演进时静默漏项）。
func snapshotRefs(note string) []string {
	const key = "snapshot_ref="
	i := strings.Index(note, key)
	if i < 0 {
		return nil
	}
	rest := strings.TrimSpace(note[i+len(key):])
	if rest == "" {
		return nil
	}
	return []string{rest}
}

func renderChain(ch Chain, n Notice) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 线索通报证据链交付包\n\n")
	fmt.Fprintf(&b, "- 通报单号：%s\n- 通报目标：%s（时限 %dh）\n- 涉事单位租户：%s；关联台账：%s\n",
		ch.NoticeID, ch.Target, n.DeadlineH, ch.Tenant, ch.LedgerID)
	fmt.Fprintf(&b, "- 生成时间：%s\n- 三要素（CR-002）：材料哈希 %s / 发起时间 %s / 目标 %s\n",
		ch.GeneratedAt.Format(time.RFC3339), n.MaterialHash, n.CreatedAt.Format(time.RFC3339), n.Target)
	if n.Status == StatusSubmitted {
		fmt.Fprintf(&b, "- 报送状态：已报送（回执 %s，%s）\n", n.ReceiptNo, n.SubmittedAt.UTC().Format(time.RFC3339))
	} else {
		fmt.Fprintf(&b, "- 报送状态：待报送（超时=%v）\n", n.Overdue)
	}
	fmt.Fprintf(&b, "\n## 证据链（可核验 %d 项 / 不可核验 %d 项）\n\n", ch.Verified, ch.Unresolved)
	for i, it := range ch.Items {
		if it.Resolved {
			fmt.Fprintf(&b, "%d. [verified] %s\n   - ref：%s\n   - SHA-256：%s\n   - 字节：%d；后端：%s\n",
				i+1, it.Role, it.Ref, it.SHA256, it.Bytes, it.Backend)
		} else {
			fmt.Fprintf(&b, "%d. [unresolved] %s\n   - ref：%s\n   - 原因：%s\n", i+1, it.Role, it.Ref, it.Error)
		}
	}
	fmt.Fprintf(&b, "\n## 整链与复核\n\n- 证据链清单 SHA-256：%s\n- 复核方式：对每项 ref 调 `GET /v1/evidence?ref=…&tenant=%s` 取回字节后做 SHA-256，应等于本清单记载值\n",
		ch.ContentHash, ch.Tenant)
	if ch.Unresolved > 0 {
		fmt.Fprintf(&b, "- **注意：本包含 %d 项不可核验证据，交付前应补齐或说明原因（不以部分证据冒充完整链条）。**\n", ch.Unresolved)
	}
	fmt.Fprintf(&b, "\n> 通用模板（过渡形态）：定稿格式与报送通道待 G8-02。\n")
	return b.String()
}

// ---- 材料与模板（过渡形态通用模板，定稿格式随 G8-02）----

func (s *Service) renderMaterial(n Notice, it ledger.Item) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 互联网敏感信息泄露线索通报\n\n")
	fmt.Fprintf(&b, "- 通报单号：%s\n", n.ID)
	fmt.Fprintf(&b, "- 通报目标：%s（时限 %dh：%s 起，%s 止）\n", n.Target, n.DeadlineH,
		n.CreatedAt.Format(time.RFC3339), n.DueAt().Format(time.RFC3339))
	fmt.Fprintf(&b, "- 发起时间：%s\n", n.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "- 涉事单位租户：%s\n\n", n.Tenant)
	fmt.Fprintf(&b, "## 线索事实（取自风险台账 %s）\n\n", it.ID)
	fmt.Fprintf(&b, "- 问题描述：%s\n", it.Title)
	fmt.Fprintf(&b, "- 关联资产/载体：%s\n", it.Asset)
	fmt.Fprintf(&b, "- 敏感数据分类：%s；风险等级：%s\n", it.Category, it.Level)
	fmt.Fprintf(&b, "- 发现阶段：%s；排查来源：%s；发现日期：%s\n", it.Phase, it.Source, it.Found.Format(time.RFC3339))
	fmt.Fprintf(&b, "- 处置措施：%s；责任部门：%s；完成时限：%s\n", it.Action, it.Owner, it.Due.Format(time.RFC3339))
	if it.Note != "" {
		fmt.Fprintf(&b, "- 证据锚点：%s\n", it.Note)
	}
	// 材料哈希与回溯 ref 均记录在通报单（列）上，不内嵌于文本——
	// 「文本自含其自身哈希/自身对象地址」在密码学上不成立（自引用），故二者只能外置。
	fmt.Fprintf(&b, "\n## 取证与固化\n\n- 材料哈希、回溯 ref、发起时间三要素记录于通报单（CR-002，落库列锁定不可改写）\n- 校验方式：对本材料做 SHA-256，应等于通报单 material_hash 字段\n")
	fmt.Fprintf(&b, "\n> 本材料由 EASM 平台生成（通用模板，过渡形态）；报送通道与定稿格式待 G8-02 确认。\n")
	return b.String()
}

func renderSummary(r Report, items []ledger.Item) string {
	byLevel := map[string]int{}
	byCat := map[string]int{}
	byStatus := map[string]int{}
	var high []ledger.Item // 突出问题候选=严重/高（已闭环的也是「排查发现」的事实）
	for _, i := range items {
		byLevel[i.Level]++
		byCat[i.Category]++
		byStatus[i.Status]++
		if i.Level == "严重" || i.Level == "高" {
			high = append(high, i)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# 互联网敏感信息泄露排查整治工作总结\n\n")
	fmt.Fprintf(&b, "- 报送租户：%s；生成时间：%s\n", r.Tenant, r.GeneratedAt.Format(time.RFC3339))
	if !r.PeriodFrom.IsZero() && !r.PeriodTo.IsZero() {
		fmt.Fprintf(&b, "- 统计区间：%s ~ %s\n", r.PeriodFrom.Format("2006-01-02"), r.PeriodTo.Format("2006-01-02"))
	}
	fmt.Fprintf(&b, "- 台账条目：%d；线索通报已报送：%d；超时未报送：%d\n\n", r.ItemCount, r.NoticeSent, r.NoticeOpen)

	fmt.Fprintf(&b, "## 一、排查发现突出问题\n\n")
	fmt.Fprintf(&b, "- 累计入账风险条目 %d 项，按等级：严重 %d / 高 %d / 中 %d；\n", r.ItemCount, byLevel["严重"], byLevel["高"], byLevel["中"])
	if len(byCat) > 0 {
		var cats []string
		for k, v := range byCat {
			cats = append(cats, fmt.Sprintf("%s %d 项", k, v))
		}
		sort.Strings(cats)
		fmt.Fprintf(&b, "- 按敏感数据分类：%s；\n", strings.Join(cats, "、"))
	}
	for _, i := range head(high, 5) {
		fmt.Fprintf(&b, "- 突出问题（%s）：%s（载体 %s，%s 发现于 %s）\n", i.Level, i.Title, i.Asset, i.Source, i.Found.Format("2006-01-02"))
	}

	fmt.Fprintf(&b, "\n## 二、整改措施及成效\n\n")
	fmt.Fprintf(&b, "- 状态分布：待整改 %d / 整改中 %d / 待通报 %d / 已闭环 %d；\n",
		byStatus[ledger.StatusOpen], byStatus[ledger.StatusDoing], byStatus[ledger.StatusNotify], byStatus[ledger.StatusClosed])
	fmt.Fprintf(&b, "- 处置措施执行（7 类措施矩阵）：按条目登记措施与责任部门，闭环须经复测验证（禁止造假闭环）；\n")
	fmt.Fprintf(&b, "- 线索通报：已报送 %d 次（回执号留痕），超时未报送 %d 项已进入催办标识。\n", r.NoticeSent, r.NoticeOpen)

	fmt.Fprintf(&b, "\n## 三、长效机制建设情况\n\n")
	fmt.Fprintf(&b, "- 排查治理：五阶段工作流 + 判敏规则 + 检索语法库常态化；\n")
	fmt.Fprintf(&b, "- 数据底座：风险台账、授权范围、证据 WORM、审计仅追加全部落库（跨重启不丢）；\n")
	fmt.Fprintf(&b, "- 外部延伸：外部渠道巡查、暗网兜底线索包、平台处置工单五态跟踪已接入；\n")
	fmt.Fprintf(&b, "- 合规闸口：授权一票否决、时间窗与限速消费、二次授权护栏在执行链路强制生效。\n")
	fmt.Fprintf(&b, "\n> 结构依据 FR-LGR-008 / FR-RPT-005；正文数字由台账与通报事实实时汇总（可复算）。通用模板，定稿格式待 G8-02。\n")
	return b.String()
}

func head(xs []ledger.Item, n int) []ledger.Item {
	if len(xs) <= n {
		return xs
	}
	return xs[:n]
}

func (s *Service) stamp(n *Notice, now time.Time) { n.Overdue = n.isOverdue(now) }

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
