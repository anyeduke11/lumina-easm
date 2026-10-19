// MVP 本地化（无容器）：graph.Store 的 PostgreSQL 实现。
// 本体与内存/Neo4j 实现完全一致（FR-GPH-001~003）；同指纹 upsert 走 ON CONFLICT merge，
// 端点不存在的边写入直接失败（引用完整性，替代 Neo4j MATCH 语义）。
package pgstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/lib/pq"

	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
)

type PGGraph struct{ db *DB }

func (d *DB) Graph() *PGGraph { return &PGGraph{d} }

func (g *PGGraph) FindByFingerprint(ctx context.Context, tenant, fp string) (graph.Entity, bool, error) {
	var (
		e         graph.Entity
		propsJSON []byte
		sources   pq.StringArray
	)
	err := g.db.sql.QueryRowContext(ctx,
		`SELECT kind, props, first_seen, last_seen, in_scope, sources
FROM graph_nodes WHERE tenant_id=$1 AND fingerprint=$2`, tenant, fp).
		Scan(&e.Kind, &propsJSON, &e.FirstSeen, &e.LastSeen, &e.InScope, &sources)
	if errors.Is(err, sql.ErrNoRows) {
		return graph.Entity{}, false, nil
	}
	if err != nil {
		return graph.Entity{}, false, err
	}
	e.Tenant, e.Fingerprint = tenant, fp
	e.Sources = []string(sources)
	_ = json.Unmarshal(propsJSON, &e.Props)
	return e, true, nil
}

// SaveEntity 幂等 upsert：last_seen 取更晚；props 合并；sources 并集去重（FR-GPH-002）。
func (g *PGGraph) SaveEntity(ctx context.Context, e graph.Entity, _ bool) error {
	propsJSON, _ := json.Marshal(e.Props)
	_, err := g.db.sql.ExecContext(ctx, `
INSERT INTO graph_nodes (fingerprint, tenant_id, kind, props, first_seen, last_seen, in_scope, sources)
VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8)
ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
  props      = graph_nodes.props || EXCLUDED.props,
  first_seen = LEAST(graph_nodes.first_seen, EXCLUDED.first_seen),
  last_seen  = GREATEST(graph_nodes.last_seen, EXCLUDED.last_seen),
  in_scope   = graph_nodes.in_scope OR EXCLUDED.in_scope,
  sources    = (SELECT array_agg(DISTINCT s) FROM unnest(graph_nodes.sources || EXCLUDED.sources) s)`,
		e.Fingerprint, e.Tenant, e.Kind, string(propsJSON), e.FirstSeen, e.LastSeen, e.InScope, pq.Array(textArr(e.Sources)))
	return err
}

func (g *PGGraph) UpsertRelation(ctx context.Context, rel graph.Relation) error {
	propsJSON, _ := json.Marshal(rel.Props)
	// 端点存在性校验（等价 Neo4j MATCH ... MERGE）
	var n int
	if err := g.db.sql.QueryRowContext(ctx,
		`SELECT count(*) FROM graph_nodes WHERE tenant_id=$1 AND fingerprint = ANY($2)`,
		rel.Tenant, pq.Array([]string{rel.FromFP, rel.ToFP})).Scan(&n); err != nil {
		return err
	}
	if n < 2 {
		return graph.ErrEndpoints
	}
	_, err := g.db.sql.ExecContext(ctx, `
INSERT INTO graph_edges (tenant_id, rel_type, from_fp, to_fp, props, evidence, ts)
VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)
ON CONFLICT (tenant_id, rel_type, from_fp, to_fp) DO UPDATE SET
  props = EXCLUDED.props, evidence = EXCLUDED.evidence, ts = EXCLUDED.ts`,
		rel.Tenant, rel.Type, rel.FromFP, rel.ToFP, string(propsJSON), rel.EvidenceRef, rel.TS)
	return err
}

// Neighbors 一跳邻接查询（FR-GPH-004 的 MVP 子集）。
func (g *PGGraph) Neighbors(ctx context.Context, tenant, fp string) ([]graph.Relation, error) {
	rs, err := g.db.sql.QueryContext(ctx,
		`SELECT rel_type, from_fp, to_fp, evidence, ts FROM graph_edges
WHERE tenant_id=$1 AND (from_fp=$2 OR to_fp=$2) ORDER BY ts`, tenant, fp)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []graph.Relation
	for rs.Next() {
		var r graph.Relation
		if err := rs.Scan(&r.Type, &r.FromFP, &r.ToFP, &r.EvidenceRef, &r.TS); err != nil {
			return nil, err
		}
		r.Tenant = tenant
		out = append(out, r)
	}
	return out, rs.Err()
}

// Entities 枚举租户实体（与 graph.MemStore 同契约：按指纹排序=确定性）。
// M3-C：密钥度量从图谱读回判定分布（跨重启保留），并供验证侧确认来源锚点存在。
func (g *PGGraph) Entities(ctx context.Context, tenant string) ([]graph.Entity, error) {
	rs, err := g.db.sql.QueryContext(ctx,
		`SELECT kind, fingerprint, props, in_scope, sources FROM graph_nodes
		  WHERE tenant_id=$1 ORDER BY fingerprint`, tenant)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []graph.Entity
	for rs.Next() {
		var (
			e    graph.Entity
			raw  []byte
			srcs pq.StringArray
		)
		if err := rs.Scan(&e.Kind, &e.Fingerprint, &raw, &e.InScope, &srcs); err != nil {
			return nil, err
		}
		e.Tenant, e.Sources = tenant, []string(srcs)
		props := map[string]string{}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &props)
		}
		e.Props = props
		out = append(out, e)
	}
	return out, rs.Err()
}

var _ graph.Store = (*PGGraph)(nil)
