// Package inventory 实现 EASM 资产身份与观察流（Phase 1 / FR-AST-001/FR-DSC-012）。
//
// 规范资产（Asset）+ 别名（Alias）+ 原始观察（Observation，append-only）：
// 同一实体多次命中走 canonical key / alias 合并，不产生重复资产；观察保留来源与时间，
// 当前态是可重建投影。entity_id 是数据域，RLS 与 Service 双重过滤。
package inventory

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
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
)

var (
	ErrInvalid  = errors.New("inventory: invalid request")
	ErrNotFound = errors.New("inventory: not found")
)

const (
	StateCandidate = "candidate"
	StateConfirmed = "confirmed"
	StateActive    = "active"
	StateStale     = "stale"
	StateRetired   = "retired"
)

// Asset 规范资产（当前态投影）。
type Asset struct {
	ID             string            `json:"id"`
	EntityID       string            `json:"entity_id"`
	Kind           string            `json:"kind"`
	CanonicalKey   string            `json:"canonical_key"`
	DisplayName    string            `json:"display_name"`
	State          string            `json:"state"`
	Confidence     float64           `json:"confidence"`
	FirstSeen      time.Time         `json:"first_seen"`
	LastSeen       time.Time         `json:"last_seen"`
	Sources        []string          `json:"sources,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
	StateReason    string            `json:"state_reason,omitempty"`
	StateChangedAt time.Time         `json:"state_changed_at,omitempty"`
}

// Alias 资产别名（同一实体的不同写法/来源）。
type Alias struct {
	EntityID  string    `json:"entity_id"`
	AssetID   string    `json:"asset_id"`
	AliasKey  string    `json:"alias_key"`
	AliasType string    `json:"alias_type"`
	SourceID  string    `json:"source_id,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Observation 原始观察（append-only）。
type Observation struct {
	ID          string            `json:"id"`
	EntityID    string            `json:"entity_id"`
	AssetID     string            `json:"asset_id"`
	AssetKey    string            `json:"asset_key"`
	Kind        string            `json:"kind"`
	Value       string            `json:"value"`
	SourceID    string            `json:"source_id"`
	ObservedAt  time.Time         `json:"observed_at"`
	RawRef      string            `json:"raw_ref,omitempty"`
	PayloadHash string            `json:"payload_hash"`
	Payload     map[string]string `json:"payload,omitempty"`
}

// Store 持久化端口（MemStore / pgstore.InventoryStore）。
type Store interface {
	UpsertAsset(ctx context.Context, a Asset) (Asset, error)
	Get(ctx context.Context, entityID, id string) (Asset, error)
	List(ctx context.Context, entityID string, limit int) ([]Asset, error)
	AddAlias(ctx context.Context, a Alias) error
	Aliases(ctx context.Context, entityID, assetID string) ([]Alias, error)
	FindByAlias(ctx context.Context, entityID, alias string) (Asset, bool, error)
	AppendObservation(ctx context.Context, o Observation) (bool, error)
	Observations(ctx context.Context, entityID, assetID string, limit int) ([]Observation, error)
	UpdateState(ctx context.Context, entityID, assetID, to, reason string, at time.Time) (Asset, error)
}

type Service struct {
	store Store
	log   audit.Log
	now   func() time.Time
}

func New(store Store, log audit.Log) *Service {
	return &Service{store: store, log: log, now: time.Now}
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Normalize 把外部取值归一为 canonical kind/key/display。
// 复用 graph.Fingerprint，保证资产身份与 Exposure Graph 同一口径。
func Normalize(kind, value string) (canonicalKind, key, display string, err error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", "", fmt.Errorf("%w: value 必填", ErrInvalid)
	}
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "domain", "dns":
		k := graph.KindDomain
		return "domain", graph.Fingerprint(k, map[string]string{"value": value}), graph.NormalizeDomain(value), nil
	case "ip", "ipv4", "ipv6":
		k := graph.KindIPBlock
		key := graph.Fingerprint(k, map[string]string{"cidr": value})
		if key == "" {
			return "", "", "", fmt.Errorf("%w: 非法 IP %q", ErrInvalid, value)
		}
		return "ip", key, value, nil
	case "url", "web", "webapp":
		k := graph.KindWebApp
		key := graph.Fingerprint(k, map[string]string{"url": value})
		if key == "" {
			return "", "", "", fmt.Errorf("%w: 非法 URL %q", ErrInvalid, value)
		}
		return "url", key, graph.NormalizeURL(value), nil
	case "repo", "repository":
		k := graph.KindCodeRepo
		key := graph.Fingerprint(k, map[string]string{"url": value})
		if key == "" {
			return "", "", "", fmt.Errorf("%w: 非法 repo URL %q", ErrInvalid, value)
		}
		return "repo", key, value, nil
	case "org", "organization", "entity":
		k := graph.KindOrganization
		key := graph.Fingerprint(k, map[string]string{"name": value})
		if key == "" {
			return "", "", "", fmt.Errorf("%w: 非法组织名 %q", ErrInvalid, value)
		}
		return "org", key, value, nil
	default:
		return "", "", "", fmt.Errorf("%w: 不支持的 kind %q", ErrInvalid, kind)
	}
}

func assetID(entityID, kind, key string) string {
	return "INV-" + sha(entityID + "|" + kind + "|" + key)[:12]
}

// Ingest 归一 + 合并/新建资产 + 追加观察 + 别名。返回 created=是否新建资产。
func (s *Service) Ingest(ctx context.Context, entityID string, in Observation) (Asset, bool, error) {
	if strings.TrimSpace(entityID) == "" || strings.TrimSpace(in.SourceID) == "" {
		return Asset{}, false, fmt.Errorf("%w: entity_id / source_id 必填", ErrInvalid)
	}
	kind, key, display, err := Normalize(in.Kind, in.Value)
	if err != nil {
		return Asset{}, false, err
	}
	now := in.ObservedAt
	if now.IsZero() {
		now = s.now().UTC()
	}
	// 别名优先：同一 URL/域名写法历史命中过，则归并到既有资产。
	id := assetID(entityID, kind, key)
	if cur, ok, err := s.store.FindByAlias(ctx, entityID, strings.ToLower(display)); err != nil {
		return Asset{}, false, err
	} else if ok {
		id = cur.ID
	}
	a := Asset{
		ID: id, EntityID: entityID, Kind: kind, CanonicalKey: key,
		DisplayName: display, State: StateCandidate,
		Confidence: 0.5, FirstSeen: now, LastSeen: now,
		Sources:    []string{in.SourceID},
		Attributes: map[string]string{"value": display},
	}
	merged, created, err := s.upsert(ctx, a)
	if err != nil {
		return Asset{}, false, err
	}
	obs := in
	obs.ID = "OBS-" + sha(entityID + "|" + in.SourceID + "|" + key + "|" + in.Value)[:12]
	obs.EntityID = entityID
	obs.AssetID = merged.ID
	obs.AssetKey = key
	obs.Kind = kind
	obs.ObservedAt = now
	if obs.Payload == nil {
		obs.Payload = map[string]string{}
	}
	obs.PayloadHash = sha(entityID + "|" + in.SourceID + "|" + key + "|" + in.Value + "|" + fmt.Sprint(obs.Payload))
	if _, err := s.store.AppendObservation(ctx, obs); err != nil {
		return Asset{}, false, err
	}
	for _, alias := range []string{strings.ToLower(display), strings.ToLower(strings.TrimSpace(in.Value))} {
		if alias == "" {
			continue
		}
		if err := s.store.AddAlias(ctx, Alias{
			EntityID: entityID, AssetID: merged.ID, AliasKey: alias,
			AliasType: "value", SourceID: in.SourceID, FirstSeen: now, LastSeen: now,
		}); err != nil {
			return Asset{}, false, err
		}
	}
	if s.log != nil {
		_ = s.log.Append(ctx, audit.Entry{Actor: in.SourceID, Action: "inventory.ingest", Resource: merged.ID, Result: audit.ResultAllow})
	}
	return merged, created, nil
}

func (s *Service) upsert(ctx context.Context, a Asset) (Asset, bool, error) {
	existing, ok, err := s.store.FindByAlias(ctx, a.EntityID, strings.ToLower(a.DisplayName))
	if err != nil {
		return a, false, err
	}
	if ok {
		a.ID = existing.ID
	}
	// FindByAlias 只覆盖别名；canonical key 走 UpsertAsset 的冲突合并。
	_, gerr := s.store.Get(ctx, a.EntityID, a.ID)
	created := errors.Is(gerr, ErrNotFound)
	if gerr != nil && !created {
		return a, false, gerr
	}
	merged, err := s.store.UpsertAsset(ctx, a)
	if err != nil {
		return a, false, err
	}
	return merged, created, nil
}

func (s *Service) Get(ctx context.Context, entityID, id string) (Asset, error) {
	if strings.TrimSpace(entityID) == "" || strings.TrimSpace(id) == "" {
		return Asset{}, ErrInvalid
	}
	return s.store.Get(ctx, entityID, id)
}

// AllowedTransition 资产状态机：candidate -> confirmed -> active <-> stale -> retired。
func AllowedTransition(from, to string) bool {
	if from == to {
		return true
	}
	switch from {
	case StateCandidate:
		return to == StateConfirmed || to == StateRetired
	case StateConfirmed:
		return to == StateActive || to == StateStale || to == StateRetired
	case StateActive:
		return to == StateStale || to == StateRetired
	case StateStale:
		return to == StateActive || to == StateRetired
	default:
		return false
	}
}

// SetState 执行状态迁移；retired 必须给出原因。同态幂等。
func (s *Service) SetState(ctx context.Context, entityID, assetID, to, reason, by string) (Asset, error) {
	to = strings.ToLower(strings.TrimSpace(to))
	if !oneOfState(to) {
		return Asset{}, fmt.Errorf("%w: 非法 state %q", ErrInvalid, to)
	}
	if to == StateRetired && strings.TrimSpace(reason) == "" {
		return Asset{}, fmt.Errorf("%w: retired 必须给出 reason", ErrInvalid)
	}
	a, err := s.store.Get(ctx, entityID, assetID)
	if err != nil {
		return Asset{}, err
	}
	if !AllowedTransition(a.State, to) {
		return Asset{}, fmt.Errorf("%w: %s -> %s 不允许", ErrInvalid, a.State, to)
	}
	if a.State == to {
		return a, nil
	}
	out, err := s.store.UpdateState(ctx, entityID, assetID, to, reason, s.now().UTC())
	if err != nil {
		return Asset{}, err
	}
	if s.log != nil {
		_ = s.log.Append(ctx, audit.Entry{Actor: by, Action: "inventory.state", Resource: assetID, Result: audit.ResultAllow})
	}
	return out, nil
}

// Decay 按最近观察时间批量衰减：超过 staleAfter -> stale，超过 retireAfter -> retired。
func (s *Service) Decay(ctx context.Context, entityID string, staleAfter, retireAfter time.Duration, by string) (int, error) {
	if staleAfter <= 0 || retireAfter <= 0 || retireAfter <= staleAfter {
		return 0, fmt.Errorf("%w: 需 0 < stale_after < retire_after", ErrInvalid)
	}
	assets, err := s.store.List(ctx, entityID, 1000)
	if err != nil {
		return 0, err
	}
	now := s.now().UTC()
	changed := 0
	for _, a := range assets {
		age := now.Sub(a.LastSeen)
		to, reason := "", ""
		switch {
		case age > retireAfter && a.State != StateRetired:
			to, reason = StateRetired, "auto-decay: 超过保留期无观察"
		case age > staleAfter && (a.State == StateConfirmed || a.State == StateActive):
			to, reason = StateStale, "auto-decay: 超过活跃期无观察"
		}
		if to == "" {
			continue
		}
		if _, err := s.SetState(ctx, entityID, a.ID, to, reason, by); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

func oneOfState(s string) bool {
	return s == StateCandidate || s == StateConfirmed || s == StateActive || s == StateStale || s == StateRetired
}

func (s *Service) List(ctx context.Context, entityID string, limit int) ([]Asset, error) {
	if strings.TrimSpace(entityID) == "" {
		return nil, ErrInvalid
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return s.store.List(ctx, entityID, limit)
}

func (s *Service) Aliases(ctx context.Context, entityID, assetID string) ([]Alias, error) {
	return s.store.Aliases(ctx, entityID, assetID)
}

func (s *Service) Observations(ctx context.Context, entityID, assetID string, limit int) ([]Observation, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return s.store.Observations(ctx, entityID, assetID, limit)
}

// MemStore 进程内实现（单测/演示）。
type MemStore struct {
	mu      sync.RWMutex
	assets  map[string]Asset
	aliases map[string]Alias // entity|alias -> alias
	obs     map[string]Observation
}

func NewMemStore() *MemStore {
	return &MemStore{assets: map[string]Asset{}, aliases: map[string]Alias{}, obs: map[string]Observation{}}
}

func aliasKey(entityID, alias string) string { return entityID + "|" + alias }

func (s *MemStore) UpsertAsset(_ context.Context, a Asset) (Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.assets[a.ID]; ok {
		cur.LastSeen = later(cur.LastSeen, a.LastSeen)
		cur.FirstSeen = earlier(cur.FirstSeen, a.FirstSeen)
		cur.Sources = union(cur.Sources, a.Sources)
		if a.Confidence > cur.Confidence {
			cur.Confidence = a.Confidence
		}
		if cur.Attributes == nil {
			cur.Attributes = map[string]string{}
		}
		for k, v := range a.Attributes {
			if v != "" {
				cur.Attributes[k] = v
			}
		}
		s.assets[a.ID] = cur
		return cur, nil
	}
	a.Sources = union(nil, a.Sources)
	s.assets[a.ID] = a
	return a, nil
}

func (s *MemStore) Get(_ context.Context, entityID, id string) (Asset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assets[id]
	if !ok || a.EntityID != entityID {
		return Asset{}, ErrNotFound
	}
	return a, nil
}

func (s *MemStore) List(_ context.Context, entityID string, limit int) ([]Asset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Asset, 0)
	for _, a := range s.assets {
		if a.EntityID == entityID {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemStore) AddAlias(_ context.Context, a Alias) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := aliasKey(a.EntityID, a.AliasKey)
	if cur, ok := s.aliases[k]; ok {
		cur.LastSeen = later(cur.LastSeen, a.LastSeen)
		cur.FirstSeen = earlier(cur.FirstSeen, a.FirstSeen)
		s.aliases[k] = cur
		return nil
	}
	s.aliases[k] = a
	return nil
}

func (s *MemStore) Aliases(_ context.Context, entityID, assetID string) ([]Alias, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Alias, 0)
	for _, a := range s.aliases {
		if a.EntityID == entityID && a.AssetID == assetID {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AliasKey < out[j].AliasKey })
	return out, nil
}

func (s *MemStore) FindByAlias(_ context.Context, entityID, alias string) (Asset, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.aliases[aliasKey(entityID, alias)]
	if !ok {
		return Asset{}, false, nil
	}
	asset, ok := s.assets[a.AssetID]
	return asset, ok, nil
}

func (s *MemStore) AppendObservation(_ context.Context, o Observation) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.obs[o.ID]; ok {
		return false, nil
	}
	s.obs[o.ID] = o
	return true, nil
}

func (s *MemStore) Observations(_ context.Context, entityID, assetID string, limit int) ([]Observation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Observation, 0)
	for _, o := range s.obs {
		if o.EntityID == entityID && o.AssetID == assetID {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ObservedAt.After(out[j].ObservedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemStore) UpdateState(_ context.Context, entityID, assetID, to, reason string, at time.Time) (Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.assets[assetID]
	if !ok || a.EntityID != entityID {
		return Asset{}, ErrNotFound
	}
	a.State = to
	a.StateReason = reason
	a.StateChangedAt = at
	s.assets[assetID] = a
	return a, nil
}

func earlier(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func union(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range append(append([]string{}, a...), b...) {
		if s != "" {
			set[s] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
