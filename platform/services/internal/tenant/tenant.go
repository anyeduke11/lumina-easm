// Package tenant 实现租户模型与服务（FR-TEN-001~005 / DR-07）。
package tenant

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

var (
	ErrDuplicate = errors.New("tenant: duplicate id")
	ErrNotFound  = errors.New("tenant: not found")
	ErrInvalid   = errors.New("tenant: invalid request")
)

// Tenant 字段对应 FR-TEN-001；json tag 对齐 DR-07 命名（snake_case，C-6）。
type Tenant struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Short       string    `json:"short,omitempty"`
	Industry    string    `json:"industry,omitempty"`
	Level       string    `json:"level,omitempty"`
	Plan        string    `json:"plan,omitempty"`
	RootDomains []string  `json:"root_domains,omitempty"`
	CIDRs       []string  `json:"cidrs,omitempty"`
	Contact     string    `json:"contact,omitempty"`
	Region      string    `json:"region,omitempty"`
	SignedAt    time.Time `json:"signed_at,omitempty"`
	ContractEnd time.Time `json:"contract_end,omitempty"`
	ThemeColor  string    `json:"theme_color,omitempty"`
	Status      string    `json:"status"`
}

type Store interface {
	Create(ctx context.Context, t Tenant) error
	Get(ctx context.Context, id string) (Tenant, error)
	List(ctx context.Context) ([]Tenant, error)
}

type MemStore struct {
	mu sync.RWMutex
	m  map[string]Tenant
}

func NewMemStore() *MemStore { return &MemStore{m: map[string]Tenant{}} }

func (s *MemStore) Create(_ context.Context, t Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[t.ID]; ok {
		return ErrDuplicate
	}
	s.m[t.ID] = t
	return nil
}

func (s *MemStore) Get(_ context.Context, id string) (Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.m[id]
	if !ok {
		return Tenant{}, ErrNotFound
	}
	return t, nil
}

func (s *MemStore) List(_ context.Context) ([]Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tenant, 0, len(s.m))
	for _, t := range s.m {
		out = append(out, t)
	}
	return out, nil
}

type Service struct {
	store Store
	log   audit.Log
}

func NewService(store Store, log audit.Log) *Service {
	return &Service{store: store, log: log}
}

func (s *Service) Create(ctx context.Context, p rbac.Principal, requestID string, t Tenant) error {
	if !p.Can(rbac.PermManageTenants) {
		_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: "tenant.create", TenantID: t.ID, Result: audit.ResultDeny, RequestID: requestID})
		return rbac.ErrForbidden
	}
	if t.ID == "" || t.Name == "" {
		return ErrInvalid
	}
	if err := s.store.Create(ctx, t); err != nil {
		return err
	}
	_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: "tenant.create", TenantID: t.ID, Resource: t.ID, Result: audit.ResultAllow, RequestID: requestID})
	return nil
}

// List 按主体 Scope 过滤——即使存储层全量可访问，也不得泄露非授权租户（一票否决④）。
func (s *Service) List(ctx context.Context, p rbac.Principal) ([]Tenant, error) {
	all, err := s.store.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Tenant, 0, len(all))
	for _, t := range all {
		if p.InScope(t.ID) {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Service) Get(ctx context.Context, p rbac.Principal, requestID, id string) (Tenant, error) {
	if !p.InScope(id) {
		_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: "tenant.read", TenantID: id, Resource: id, Result: audit.ResultDeny, RequestID: requestID})
		return Tenant{}, rbac.ErrCrossTenant
	}
	return s.store.Get(ctx, id)
}
