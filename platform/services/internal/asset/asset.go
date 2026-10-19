// Package asset 实现资产实体与校验（DR-01 / FR-AST-001）。
package asset

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

var (
	ErrDuplicate = errors.New("asset: duplicate id")
	ErrNotFound  = errors.New("asset: not found")
	ErrInvalid   = errors.New("asset: invalid request")
)

// Asset 对应 DR-01 字段（M0 最小集；指纹 merge 属 WP-M0-06，后续接入）。
// json tag 对齐 DR-01 命名（snake_case），保证 REST 视图与 MCP 输出同一字段口径（C-6）。
type Asset struct {
	ID        string    `json:"id"`
	Tenant    string    `json:"tenant"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	TypeLabel string    `json:"type_label,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Risk      string    `json:"risk"`
	Exp       int       `json:"exp"`
	Owner     string    `json:"owner"`
	Found     time.Time `json:"found"`
	Status    string    `json:"status"`
	Beian     string    `json:"beian"`
	Source    string    `json:"source"`
	Biz       string    `json:"biz"`
	Tags      []string  `json:"tags,omitempty"`
	AI        string    `json:"ai,omitempty"`
	Ports     []int     `json:"ports,omitempty"`
	Tech      []string  `json:"tech,omitempty"`
}

func oneOf(v string, set ...string) bool {
	for _, s := range set {
		if v == s {
			return true
		}
	}
	return false
}

// Validate 返回问题清单；必填缺失即拒绝入账（FR-AST-001 / A-07 / C-6 枚举口径）。
func (a Asset) Validate() []string {
	var bad []string
	req := []struct {
		field string
		val   string
	}{
		{"ID", a.ID}, {"Tenant", a.Tenant}, {"Name", a.Name}, {"Type", a.Type},
		{"Risk", a.Risk}, {"Owner", a.Owner}, {"Status", a.Status}, {"Beian", a.Beian}, {"Source", a.Source},
	}
	for _, f := range req {
		if strings.TrimSpace(f.val) == "" {
			bad = append(bad, f.field+" 缺失")
		}
	}
	if a.Found.IsZero() {
		bad = append(bad, "Found 缺失")
	}
	if a.Type != "" && !oneOf(a.Type, "domain", "ip", "port", "web", "cert", "credential", "doc", "repo", "cloud", "person", "org") {
		bad = append(bad, fmt.Sprintf("Type 非法: %q", a.Type))
	}
	if a.Risk != "" && !oneOf(a.Risk, "critical", "high", "medium", "low", "info") {
		bad = append(bad, fmt.Sprintf("Risk 非法: %q", a.Risk))
	}
	if a.Status != "" && !oneOf(a.Status, "在用", "闲置", "废弃") {
		bad = append(bad, fmt.Sprintf("Status 非法: %q", a.Status))
	}
	if a.Beian != "" && !oneOf(a.Beian, "已备案", "未备案", "备案中") {
		bad = append(bad, fmt.Sprintf("Beian 非法: %q", a.Beian))
	}
	if a.Exp < 0 || a.Exp > 100 {
		bad = append(bad, "Exp 须在 0–100")
	}
	return bad
}

type Store interface {
	Create(ctx context.Context, a Asset) error
	Get(ctx context.Context, id string) (Asset, error)
	Delete(ctx context.Context, id string) error
	ListByTenant(ctx context.Context, tenantID string) ([]Asset, error)
}

type MemStore struct {
	mu sync.RWMutex
	m  map[string]Asset
}

func NewMemStore() *MemStore { return &MemStore{m: map[string]Asset{}} }

func (s *MemStore) Create(_ context.Context, a Asset) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[a.ID]; ok {
		return ErrDuplicate
	}
	s.m[a.ID] = a
	return nil
}

func (s *MemStore) Get(_ context.Context, id string) (Asset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.m[id]
	if !ok {
		return Asset{}, ErrNotFound
	}
	return a, nil
}

func (s *MemStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
	return nil
}

func (s *MemStore) ListByTenant(_ context.Context, tenantID string) ([]Asset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Asset, 0)
	for _, a := range s.m {
		if a.Tenant == tenantID {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

type Service struct {
	store Store
	log   audit.Log
	sync  SyncFunc // 入账→图谱投影（WP-M0-06 联动）；nil 时跳过
}

// SyncFunc 在资产成功入账后被调用，把资产投影为图谱实体/关系（FR-DSC-012）。
// 返回错误则整笔 Create 失败——图谱是事实源（AX-1），不允许台账与图谱静默分叉。
type SyncFunc func(ctx context.Context, a Asset) error

func NewService(store Store, log audit.Log) *Service {
	return &Service{store: store, log: log}
}

// SetAssetSync 由装配层（cmd/server）注入投影函数，保持 asset 包不依赖 graph 包。
func (s *Service) SetAssetSync(fn SyncFunc) { s.sync = fn }

func (s *Service) Create(ctx context.Context, p rbac.Principal, requestID string, a Asset) (Asset, error) {
	if !p.Can(rbac.PermWriteAssets) {
		_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: "asset.create", TenantID: a.Tenant, Resource: a.ID, Result: audit.ResultDeny, RequestID: requestID})
		return a, rbac.ErrForbidden
	}
	if !p.InScope(a.Tenant) {
		_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: "asset.create", TenantID: a.Tenant, Resource: a.ID, Result: audit.ResultDeny, RequestID: requestID})
		return a, rbac.ErrCrossTenant
	}
	if bad := a.Validate(); len(bad) > 0 {
		return a, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(bad, "; "))
	}
	if err := s.store.Create(ctx, a); err != nil {
		return a, err
	}
	if s.sync != nil {
		if err := s.sync(ctx, a); err != nil {
			// 补偿回滚（遗留①销账）：图谱是事实源，投影失败不允许台账单方面领先——
			// 删除刚入账的行后返回错误，保证「资产存在 ⇒ 图谱可投影」不变式。
			_ = s.store.Delete(ctx, a.ID)
			return a, fmt.Errorf("图谱投影失败（入账已回滚）: %w", err)
		}
	}
	_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: "asset.create", TenantID: a.Tenant, Resource: a.ID, Result: audit.ResultAllow, RequestID: requestID})
	return a, nil
}

func (s *Service) GetByID(ctx context.Context, p rbac.Principal, requestID, id string) (Asset, error) {
	a, err := s.store.Get(ctx, id)
	if err != nil {
		return Asset{}, err
	}
	if !p.InScope(a.Tenant) {
		_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: "asset.read", TenantID: a.Tenant, Resource: id, Result: audit.ResultDeny, RequestID: requestID})
		return Asset{}, rbac.ErrCrossTenant
	}
	return a, nil
}

func (s *Service) ListByTenant(ctx context.Context, p rbac.Principal, requestID, tenantID string) ([]Asset, error) {
	if !p.Can(rbac.PermReadAssets) {
		_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: "asset.list", TenantID: tenantID, Result: audit.ResultDeny, RequestID: requestID})
		return nil, rbac.ErrForbidden
	}
	if !p.InScope(tenantID) {
		_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: "asset.list", TenantID: tenantID, Result: audit.ResultDeny, RequestID: requestID})
		return nil, rbac.ErrCrossTenant
	}
	return s.store.ListByTenant(ctx, tenantID)
}
