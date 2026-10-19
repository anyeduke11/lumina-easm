// Package authz 实现扫描授权范围校验（FR-DSC-013 / CR-005 / NFR-SEC-009 / 一票否决⑥）。
// auth_scope 字段规范对齐设计方案 §11.1：域名/IP 段/端口/排除项/有效期/限速/时间窗口/二次授权/签署人。
// 白名单外目标一律拒绝并审计；授权过期自动失效（无需人工删）。
package authz

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

var (
	ErrInvalidScope = errors.New("authz: invalid scope")
	ErrNotInScope   = errors.New("authz: target not in authorized scope")
	ErrNoScope      = errors.New("authz: tenant has no valid authorization scope")
	ErrNoSecondAuth = errors.New("authz: high-risk action requires second authorization")
	ErrNotInWindow  = errors.New("authz: outside authorized time window（窗口外不执行主动测试）")
)

// Scope 一份有效授权（对应授权书数字化形态）。
type Scope struct {
	Tenant     string    `json:"tenant"`
	Domains    []string  `json:"domains"`         // 含其子域
	CIDRs      []string  `json:"cidrs"`           // 单 IP 写 x.x.x.x/32
	Ports      []int     `json:"ports,omitempty"` // 空=不限
	Excludes   []string  `json:"excludes,omitempty"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidTo    time.Time `json:"valid_to"`
	RateLimit  int       `json:"rate_limit"`  // 令牌桶参数（G8-06 下发）
	TimeWindow string    `json:"time_window"` // 如 "00:00-08:00"
	SecondAuth bool      `json:"second_auth"` // 弱口令/爆破类二次授权
	Signer     string    `json:"signer"`      // 签署主体
	DocHash    string    `json:"doc_hash"`    // 授权文件哈希（CR-001 取证）
}

func (sc Scope) validate() error {
	if sc.Tenant == "" || sc.ValidFrom.IsZero() || sc.ValidTo.IsZero() || !sc.ValidTo.After(sc.ValidFrom) {
		return ErrInvalidScope
	}
	for _, c := range sc.CIDRs {
		if _, err := netip.ParsePrefix(c); err != nil {
			if _, err := netip.ParseAddr(c); err != nil {
				return errors.New("authz: 非法 IP/CIDR " + c)
			}
		}
	}
	if sc.TimeWindow != "" { // 录入即验格式：防「写了不生效」的静默（合同承诺项）
		if _, _, err := parseWindow(sc.TimeWindow); err != nil {
			return err
		}
	}
	return nil
}

func (sc Scope) active(now time.Time) bool {
	return !now.Before(sc.ValidFrom) && now.Before(sc.ValidTo)
}

// parseWindow 解析 "HH:MM-HH:MM" 为当日分钟数对。
func parseWindow(w string) (start, end int, err error) {
	var h1, m1, h2, m2 int
	if n, _ := fmt.Sscanf(w, "%d:%d-%d:%d", &h1, &m1, &h2, &m2); n != 4 {
		return 0, 0, fmt.Errorf("authz: 非法 time_window %q（须 HH:MM-HH:MM）", w)
	}
	if h1 > 23 || h2 > 23 || m1 > 59 || m2 > 59 {
		return 0, 0, fmt.Errorf("authz: 非法 time_window %q", w)
	}
	return h1*60 + m1, h2*60 + m2, nil
}

// inWindow 判定 now（UTC）是否在授权时间窗内：空=不限；start<end 当日区间；
// start>end 跨日；start==end 全天。
func (sc Scope) inWindow(now time.Time) bool {
	if sc.TimeWindow == "" {
		return true
	}
	s, e, err := parseWindow(sc.TimeWindow)
	if err != nil { // validate() 已挡；防御性按「不限」会被误用——fail loud：视为拒绝
		return false
	}
	cur := now.UTC().Hour()*60 + now.UTC().Minute()
	switch {
	case s == e:
		return true
	case s < e:
		return cur >= s && cur < e
	default: // 跨日：22:00-06:00
		return cur >= s || cur < e
	}
}

type Store interface {
	Put(ctx context.Context, sc Scope) error
	Get(ctx context.Context, tenant string) (Scope, bool, error)
}

type MemStore struct {
	mu sync.RWMutex
	m  map[string]Scope
}

func NewMemStore() *MemStore { return &MemStore{m: map[string]Scope{}} }

func (s *MemStore) Put(_ context.Context, sc Scope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[sc.Tenant] = sc
	return nil
}

func (s *MemStore) Get(_ context.Context, tenant string) (Scope, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sc, ok := s.m[tenant]
	return sc, ok, nil
}

type Service struct {
	store Store
	log   audit.Log
	now   func() time.Time
}

func NewService(store Store, log audit.Log) *Service {
	return &Service{store: store, log: log, now: time.Now}
}

// Upsert 仅管理角色可录入（授权录入即权限授予，须 R7/R3 口径）。
func (s *Service) Upsert(ctx context.Context, p rbac.Principal, reqID string, sc Scope) error {
	if !p.Can(rbac.PermManageTenants) {
		_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: "authz.upsert", TenantID: sc.Tenant, Result: audit.ResultDeny, RequestID: reqID})
		return rbac.ErrForbidden
	}
	if err := sc.validate(); err != nil {
		return err
	}
	if err := s.store.Put(ctx, sc); err != nil {
		return err
	}
	_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: "authz.upsert", TenantID: sc.Tenant, Resource: sc.Signer, Result: audit.ResultAllow, RequestID: reqID})
	return nil
}

func (s *Service) Get(ctx context.Context, tenant string) (Scope, bool, error) {
	return s.store.Get(ctx, tenant)
}

// CheckTarget 执行前校验：目标（域名或 IP）+ 端口必须落在有效授权内，排除项优先。
// 拒绝路径必须留审计（CR-005：白名单外请求拒绝并记录）。
func (s *Service) CheckTarget(ctx context.Context, p rbac.Principal, reqID, tenant, target string, port int) error {
	sc, ok, err := s.store.Get(ctx, tenant)
	if err != nil || !ok || !sc.active(s.now()) {
		_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: "authz.check", TenantID: tenant, Resource: target, Result: audit.ResultDeny, RequestID: reqID})
		return ErrNoScope
	}
	if !sc.inWindow(s.now()) { // M2-01 前置：窗口承诺=运行时闸（合同兑现，拒绝必留痕）
		_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: "authz.check", TenantID: tenant, Resource: target, Result: audit.ResultDeny, RequestID: reqID})
		return ErrNotInWindow
	}
	if matchAny(sc.Excludes, target) {
		_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: "authz.check", TenantID: tenant, Resource: target, Result: audit.ResultDeny, RequestID: reqID})
		return ErrNotInScope
	}
	in := matchDomain(sc.Domains, target) || matchCIDR(sc.CIDRs, target)
	if !in {
		_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: "authz.check", TenantID: tenant, Resource: target, Result: audit.ResultDeny, RequestID: reqID})
		return ErrNotInScope
	}
	if len(sc.Ports) > 0 && port > 0 && !containsInt(sc.Ports, port) {
		_ = s.log.Append(ctx, audit.Entry{Actor: p.UserID, Action: "authz.check", TenantID: tenant, Resource: target, Result: audit.ResultDeny, RequestID: reqID})
		return ErrNotInScope
	}
	return nil
}

// Validate 供 sweep 等编排入口用：租户存在有效授权且在时间窗内即可整体放行
// （细目标由 CheckTarget 把关）；窗口拒=ErrNotInWindow（与过期同型可观测）。
func (s *Service) Validate(ctx context.Context, tenant string) error {
	sc, ok, err := s.store.Get(ctx, tenant)
	if err != nil {
		return err
	}
	if !ok || !sc.active(s.now()) {
		return ErrNoScope
	}
	if !sc.inWindow(s.now()) {
		return ErrNotInWindow
	}
	return nil
}

// RequireSecondAuth 弱口令/爆破类动作的二次授权闸（FR-LGR/护栏 5）。
func (s *Service) RequireSecondAuth(ctx context.Context, tenant string) error {
	sc, ok, err := s.store.Get(ctx, tenant)
	if err != nil {
		return err
	}
	if !ok || !sc.active(s.now()) {
		return ErrNoScope
	}
	if !sc.SecondAuth {
		return ErrNoSecondAuth
	}
	return nil
}

func matchAny(patterns []string, target string) bool {
	for _, p := range patterns {
		if matchDomain([]string{p}, target) || matchCIDR([]string{p}, target) {
			return true
		}
	}
	return false
}

func matchDomain(domains []string, target string) bool {
	t := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(target), "."))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if d == "" {
			continue
		}
		if t == d || strings.HasSuffix(t, "."+d) {
			return true
		}
	}
	return false
}

func matchCIDR(cidrs []string, target string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(target))
	if err != nil {
		return false
	}
	for _, c := range cidrs {
		if pre, err := netip.ParsePrefix(c); err == nil {
			if pre.Contains(addr) {
				return true
			}
			continue
		}
		if one, err := netip.ParseAddr(c); err == nil && one == addr {
			return true
		}
	}
	return false
}

func containsInt(list []int, v int) bool {
	for _, i := range list {
		if i == v {
			return true
		}
	}
	return false
}
