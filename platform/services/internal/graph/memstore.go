package graph

// 内存图谱 store（M3-B 新增）：内存模式此前无图谱后端（端点 501），
// 本 store 同时满足 Store 与路径推演 Source，使内存/PG 双后端契约一致。
// 数据仅存活于进程内——与其余内存 store 同口径（演示/单测，不做跨重启承诺）。

import (
	"context"
	"sync"
)

// MemStore 内存图谱 store（并发安全）。
type MemStore struct {
	mu   sync.Mutex
	ents map[string]Entity   // key=tenant|fp
	rels map[string]Relation // key=tenant|type|from|to
}

// NewMemStore 构造内存图谱 store。
func NewMemStore() *MemStore {
	return &MemStore{ents: map[string]Entity{}, rels: map[string]Relation{}}
}

func (m *MemStore) FindByFingerprint(_ context.Context, tenant, fp string) (Entity, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.ents[tenant+"|"+fp]
	return e, ok, nil
}

func (m *MemStore) SaveEntity(_ context.Context, e Entity, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ents[e.Tenant+"|"+e.Fingerprint] = e
	return nil
}

func (m *MemStore) UpsertRelation(_ context.Context, rel Relation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rels[rel.Tenant+"|"+rel.Type+"|"+rel.FromFP+"|"+rel.ToFP] = rel
	return nil
}

// Neighbors 一跳邻接（满足 ingest.Reader，内存模式图谱端点可用）。
func (m *MemStore) Neighbors(_ context.Context, tenant, fp string) ([]Relation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Relation
	for _, r := range m.rels {
		if r.Tenant == tenant && (r.FromFP == fp || r.ToFP == fp) {
			out = append(out, r)
		}
	}
	sortRelations(out)
	return out, nil
}

// Source 面：Relations/Entities（按指纹排序=确定性，与 PG 侧 ORDER BY 一致）。
func (m *MemStore) Relations(_ context.Context, tenant string) ([]Relation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Relation, 0, len(m.rels))
	for _, r := range m.rels {
		if r.Tenant == tenant {
			out = append(out, r)
		}
	}
	sortRelations(out)
	return out, nil
}

func (m *MemStore) Entities(_ context.Context, tenant string) ([]Entity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Entity, 0, len(m.ents))
	for _, e := range m.ents {
		if e.Tenant == tenant {
			out = append(out, e)
		}
	}
	sortEntities(out)
	return out, nil
}
