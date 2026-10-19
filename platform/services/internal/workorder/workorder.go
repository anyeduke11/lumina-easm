// Package workorder 实现平台处置工单（WP-M2-03 / FR-CHN-004）：命中第三方平台内容
// （代码仓库/文档网盘/社交/暗市场）生成投诉/删除工单，五态跟踪至下架：
// 待整改 → 处置中 → 已通报平台 → 已下架 → 已处置（唯一回退边 已通报平台→处置中=跟催）。
// 不可虚报闭环（AX-4 同律）：跳步转移一律拒绝；终态锁定；每步留痕（操作人/时间/备注）。
// 建单即过质量闸：必须挂同租户真实台账条目（无账可销的工单=不可闭环的材料）。
package workorder

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

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

const (
	StatusPending   = "待整改"
	StatusWorking   = "处置中"
	StatusReported  = "已通报平台"
	StatusTakenDown = "已下架"
	StatusResolved  = "已处置"
)

// transitions 五态转移表：前进主链 + 唯一跟催回退边；其余（含终态出边）非法。
var transitions = map[string][]string{
	StatusPending:   {StatusWorking},
	StatusWorking:   {StatusReported},
	StatusReported:  {StatusTakenDown, StatusWorking}, // 平台未处理/拒绝→回退跟催
	StatusTakenDown: {StatusResolved},                 // 下架事实不可撤销（回退=伪造下架）
	StatusResolved:  nil,                              // 终态锁定
}

var (
	ErrInvalid           = errors.New("workorder: 工单非法")
	ErrIllegalTransition = errors.New("workorder: 非法状态转移（跳步/回退/终态锁定）")
	ErrNotFound          = errors.New("workorder: 工单不存在")
	ErrDuplicate         = errors.New("workorder: 同台账同载体工单已存在（防重复投诉）")
	kinds                = map[string]bool{"投诉": true, "删除申请": true}
	StatusList           = []string{StatusPending, StatusWorking, StatusReported, StatusTakenDown, StatusResolved}
)

// ValidStatus 五态枚举校验（查询参数面）。
func ValidStatus(s string) bool {
	for _, st := range StatusList {
		if st == s {
			return true
		}
	}
	return false
}

// Transition 一步留痕（公安/平台复核「谁在哪步做了什么」的原始事实）。
type Transition struct {
	TS       time.Time `json:"ts"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	Operator string    `json:"operator"`
	Note     string    `json:"note,omitempty"`
}

// WorkOrder 处置工单（ID=WO-<sha12(tenant|ledger|channel|target)>：同台账同载体唯一）。
type WorkOrder struct {
	ID        string       `json:"id"`
	Tenant    string       `json:"tenant"`
	LedgerID  string       `json:"ledger_id"`
	Channel   string       `json:"channel"` // 命中渠道（repo.secret/doc.pan/social/dark.web…）
	Target    string       `json:"target"`  // 处置载体 URL/定位
	Kind      string       `json:"kind"`    // 投诉|删除申请
	Platform  string       `json:"platform"`
	Title     string       `json:"title"`
	Owner     string       `json:"owner"`
	Status    string       `json:"status"`
	Evidence  string       `json:"evidence_ref,omitempty"` // snapshot_ref（C-5 回溯）
	History   []Transition `json:"history"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// LedgerReader 台账读口（ledger.Service 满足）：建单验证关联条目存在且同租户。
type LedgerReader interface {
	Get(ctx context.Context, p rbac.Principal, reqID, id string) (ledger.Item, error)
}

type Store interface {
	Create(ctx context.Context, w WorkOrder) error
	Get(ctx context.Context, tenant, id string) (WorkOrder, error) // 租户不匹配=ErrNotFound（行级闸）
	Update(ctx context.Context, w WorkOrder) error
	List(ctx context.Context, tenant, status string) ([]WorkOrder, error)
}

type MemStore struct {
	mu sync.RWMutex
	m  map[string]WorkOrder
}

func NewMemStore() *MemStore { return &MemStore{m: map[string]WorkOrder{}} }

func (s *MemStore) Create(_ context.Context, w WorkOrder) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[w.ID]; ok {
		return ErrDuplicate
	}
	s.m[w.ID] = w
	return nil
}

func (s *MemStore) Get(_ context.Context, tenant, id string) (WorkOrder, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w, ok := s.m[id]
	if !ok || w.Tenant != tenant {
		return WorkOrder{}, ErrNotFound
	}
	return w, nil
}

func (s *MemStore) Update(_ context.Context, w WorkOrder) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[w.ID] = w
	return nil
}

func (s *MemStore) List(_ context.Context, tenant, status string) ([]WorkOrder, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []WorkOrder
	for _, w := range s.m {
		if w.Tenant == tenant && (status == "" || w.Status == status) {
			out = append(out, w)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

type Service struct {
	store Store
	log   audit.Log
	led   LedgerReader
	now   func() time.Time
}

func NewService(store Store, log audit.Log, led LedgerReader) *Service {
	return &Service{store: store, log: log, led: led, now: time.Now}
}

// Create 建单（写权限+InScope → 必填/枚举校验 → 台账关联闸（存在+同租户）→
// 待整改初始态 + 首条留痕「建单」→ 落库 + 审计）。指针入参回填 ID/状态供调用方。
func (s *Service) Create(ctx context.Context, p rbac.Principal, reqID string, w *WorkOrder) error {
	if !p.Can(rbac.PermWriteAssets) {
		s.deny(ctx, p, "workorder.create", w.Tenant, reqID)
		return rbac.ErrForbidden
	}
	if !p.InScope(w.Tenant) {
		s.deny(ctx, p, "workorder.create", w.Tenant, reqID)
		return rbac.ErrCrossTenant
	}
	if err := s.validateNew(w); err != nil {
		return err
	}
	if w.LedgerID != "" {
		it, err := s.led.Get(ctx, p, reqID, w.LedgerID)
		if err != nil {
			return fmt.Errorf("workorder: 台账关联校验失败: %w", err)
		}
		if it.Tenant != w.Tenant {
			return fmt.Errorf("%w: 台账条目属租户 %s（不得拿他账立单）", ErrInvalid, it.Tenant)
		}
	}
	now := s.now().UTC()
	w.ID = "WO-" + orderHash(w.Tenant+"|"+w.LedgerID+"|"+w.Channel+"|"+w.Target)
	w.Status = StatusPending
	w.CreatedAt, w.UpdatedAt = now, now
	w.History = []Transition{{TS: now, From: "", To: StatusPending, Operator: p.UserID, Note: "建单"}}
	if err := s.store.Create(ctx, *w); err != nil {
		return err
	}
	s.allow(ctx, p, "workorder.create", w.Tenant, w.ID, reqID)
	return nil
}

// Advance 状态转移（读权限走行级租户路径；转移表闸 → 留痕追加 → 落库 + 审计）。
// 转移失败不留痕（非法转移尝试以审计 deny 呈现，而非工单历史污染）。
func (s *Service) Advance(ctx context.Context, p rbac.Principal, reqID, tenant, id, to, operator, note string) error {
	if !p.Can(rbac.PermWriteAssets) {
		s.deny(ctx, p, "workorder.advance", tenant, reqID)
		return rbac.ErrForbidden
	}
	if !p.InScope(tenant) {
		s.deny(ctx, p, "workorder.advance", tenant, reqID)
		return rbac.ErrCrossTenant
	}
	if operator == "" {
		return fmt.Errorf("%w: 转移必须记录操作人（复核可追溯）", ErrInvalid)
	}
	w, err := s.store.Get(ctx, tenant, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return err
		}
		return err
	}
	if !canTransition(w.Status, to) {
		s.deny(ctx, p, "workorder.advance", tenant, reqID)
		return fmt.Errorf("%w: %s → %s", ErrIllegalTransition, w.Status, to)
	}
	now := s.now().UTC()
	w.History = append(w.History, Transition{TS: now, From: w.Status, To: to, Operator: operator, Note: note})
	w.Status, w.UpdatedAt = to, now
	if err := s.store.Update(ctx, w); err != nil {
		return err
	}
	s.allow(ctx, p, "workorder.advance", tenant, id, reqID)
	return nil
}

// Get 行级租户读（跨租户与不存在同响应=不泄露存在性，AX-5 口径）。
func (s *Service) Get(ctx context.Context, p rbac.Principal, reqID, tenant, id string) (WorkOrder, error) {
	if !p.Can(rbac.PermReadAssets) {
		s.deny(ctx, p, "workorder.read", tenant, reqID)
		return WorkOrder{}, rbac.ErrForbidden
	}
	if !p.InScope(tenant) {
		s.deny(ctx, p, "workorder.read", tenant, reqID)
		return WorkOrder{}, rbac.ErrCrossTenant
	}
	return s.store.Get(ctx, tenant, id)
}

// List 按租户（可选状态筛）列举。
func (s *Service) List(ctx context.Context, p rbac.Principal, reqID, tenant, status string) ([]WorkOrder, error) {
	if !p.Can(rbac.PermReadAssets) {
		s.deny(ctx, p, "workorder.list", tenant, reqID)
		return nil, rbac.ErrForbidden
	}
	if !p.InScope(tenant) {
		s.deny(ctx, p, "workorder.list", tenant, reqID)
		return nil, rbac.ErrCrossTenant
	}
	return s.store.List(ctx, tenant, status)
}

func canTransition(from, to string) bool {
	for _, t := range transitions[from] {
		if t == to {
			return true
		}
	}
	return false
}

func (s *Service) validateNew(w *WorkOrder) error {
	var bad []string
	if strings.TrimSpace(w.Tenant) == "" {
		bad = append(bad, "tenant")
	}
	if strings.TrimSpace(w.LedgerID) == "" {
		bad = append(bad, "ledger_id")
	}
	if strings.TrimSpace(w.Channel) == "" {
		bad = append(bad, "channel")
	}
	if strings.TrimSpace(w.Target) == "" {
		bad = append(bad, "target")
	}
	if strings.TrimSpace(w.Platform) == "" {
		bad = append(bad, "platform")
	}
	if strings.TrimSpace(w.Title) == "" {
		bad = append(bad, "title")
	}
	if strings.TrimSpace(w.Owner) == "" {
		bad = append(bad, "owner")
	}
	if !kinds[w.Kind] {
		bad = append(bad, "kind:"+w.Kind)
	}
	if len(bad) > 0 {
		return fmt.Errorf("%w: 缺失/非法 %s", ErrInvalid, strings.Join(bad, ","))
	}
	return nil
}

func orderHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6])
}

func (s *Service) deny(ctx context.Context, p rbac.Principal, action, tenant, reqID string) {
	_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: action, TenantID: tenant, Result: audit.ResultDeny, RequestID: reqID})
}

func (s *Service) allow(ctx context.Context, p rbac.Principal, action, tenant, res, reqID string) {
	_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: action, TenantID: tenant, Resource: res, Result: audit.ResultAllow, RequestID: reqID})
}
