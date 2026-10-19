package pgstore

// PG 侧攻击路径推演（M3-B / FR-GPH-004 双实现之一）：递归 CTE——
//   - Reachable/ShortestPath：WITH RECURSIVE 逐层展开（depth 受限，首次命中即最短）；
//   - Subgraph：以起点为种子的 k 跳递归 CTE（实体+边）；
//   - TopPaths：入口实体为种子的递归 CTE 枚举（目标种类过滤），再交给 graph.RankPaths
//     做**与内存实现共用**的确定性排序（保证双后端同图同 TopN）。
//
// 与内存实现的分工：遍历在 SQL（避免整图拉入内存），排序在 Go（契约唯一）。

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
)

// PGPath 递归 CTE 路径推演（DB.GraphPath() 装配）。
type PGPath struct{ db *DB }

// maxPathRows 路径枚举行数上限（包级变量=测试可注入）：超限**上浮报错**而非静默截断——
// 静默截断会让 TopN 悄悄少给路径=取证失真（fail loud 优于兜底）。
var maxPathRows = 2000

// PathQuery 装配入口（满足 graph.PathQuery 端口）。
func (d *DB) GraphPath() *PGPath { return &PGPath{d} }

// walkPaths 递归 CTE：返回 (start_fp, end_fp, depth, path[])。
// seededByKind=true 时以入口种类实体为种子（TopPaths）；否则单起点（可达性/最短路径）。
func (p *PGPath) walkPaths(ctx context.Context, tenant string, seeds []string, seedKinds []string,
	targets []string, maxDepth int) ([]struct {
	Start string
	End   string
	Depth int
	Path  []string
}, error) {
	if maxDepth <= 0 || maxDepth > graph.DefaultMaxDepth {
		maxDepth = graph.DefaultMaxDepth
	}
	var out []struct {
		Start string
		End   string
		Depth int
		Path  []string
	}
	// 递归 CTE：path 数组防环（NOT (to_fp = ANY(path))）
	q := `
WITH RECURSIVE walk(start_fp, fp, depth, path) AS (
  SELECT n.fingerprint, n.fingerprint, 0, ARRAY[n.fingerprint]::text[]
    FROM graph_nodes n
   WHERE n.tenant_id = $1
     AND (cardinality($2::text[]) = 0 OR n.fingerprint = ANY($2::text[]))
     AND (cardinality($3::text[]) = 0 OR n.kind = ANY($3::text[]))
  UNION ALL
  SELECT w.start_fp, e.to_fp, w.depth + 1, array_append(w.path, e.to_fp)
    FROM walk w
    JOIN graph_edges e
      ON e.tenant_id = $1 AND e.from_fp = w.fp
   WHERE w.depth < $4
     AND NOT (e.to_fp = ANY(w.path))
)
SELECT start_fp, fp, depth, path
  FROM walk
 WHERE depth > 0
   AND (cardinality($5::text[]) = 0 OR fp = ANY($5::text[]))
 ORDER BY depth, start_fp, fp
 LIMIT $6`
	// pq.Array 显式包数组：空切片必须编码为 '{}' 而非 NULL（NULL 会让
	// cardinality(...)=0 判空失效，整表被过滤=静默无路径）。
	// 多行取一条=探超限（LIMIT maxPathRows+1，若真拿到第 maxPathRows+1 行即判定枚举超限）。
	rows, err := p.db.sql.QueryContext(ctx, q, tenant, pq.Array(textArr(seeds)),
		pq.Array(textArr(seedKinds)), maxDepth, pq.Array(textArr(targets)), maxPathRows+1)
	if err != nil {
		return nil, fmt.Errorf("pgstore: 路径递归 CTE 失败: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var start, end string
		var depth int
		var path pq.StringArray // text[] 需 pq.StringArray 承载（原生 []string 无法 Scan）
		if err := rows.Scan(&start, &end, &depth, &path); err != nil {
			return nil, fmt.Errorf("pgstore: 路径行扫描失败: %w", err)
		}
		out = append(out, struct {
			Start string
			End   string
			Depth int
			Path  []string
		}{start, end, depth, []string(path)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstore: 路径行扫描失败: %w", err)
	}
	if len(out) > maxPathRows {
		// 不静默截断：宁可报错（端点 500 上浮），也不要悄悄少给路径让 TopN 看起来「就这些」。
		return nil, fmt.Errorf("pgstore: 路径枚举超出上限 %d 行（图规模/深度过大），请收窄范围后重算", maxPathRows)
	}
	return out, nil
}

// edgesOf 取租户全量边（用于把 CTE 的指纹序列还原为边序列，含 rel_type/证据）。
func (p *PGPath) edgesOf(ctx context.Context, tenant string) ([]graph.Relation, error) {
	rows, err := p.db.sql.QueryContext(ctx,
		`SELECT rel_type, from_fp, to_fp, COALESCE(evidence,''), ts FROM graph_edges
		  WHERE tenant_id = $1 ORDER BY from_fp, to_fp, rel_type`, tenant)
	if err != nil {
		return nil, fmt.Errorf("pgstore: 边读取失败: %w", err)
	}
	defer rows.Close()
	var out []graph.Relation
	for rows.Next() {
		var r graph.Relation
		r.Tenant = tenant
		if err := rows.Scan(&r.Type, &r.FromFP, &r.ToFP, &r.EvidenceRef, &r.TS); err != nil {
			return nil, fmt.Errorf("pgstore: 边扫描失败: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// kindsOf 取租户实体种类（排序优先级与目标判定需要）。
func (p *PGPath) kindsOf(ctx context.Context, tenant string) (map[string]string, error) {
	rows, err := p.db.sql.QueryContext(ctx,
		`SELECT fingerprint, kind FROM graph_nodes WHERE tenant_id = $1 ORDER BY fingerprint`, tenant)
	if err != nil {
		return nil, fmt.Errorf("pgstore: 实体读取失败: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var fp, kind string
		if err := rows.Scan(&fp, &kind); err != nil {
			return nil, err
		}
		out[fp] = kind
	}
	return out, rows.Err()
}

// Reachable 深度受限可达性（递归 CTE 首次命中=最短）。
func (p *PGPath) Reachable(ctx context.Context, tenant, from, to string, maxDepth int) (bool, []graph.Relation, error) {
	res, err := p.walkPaths(ctx, tenant, []string{from}, nil, []string{to}, maxDepth)
	if err != nil {
		return false, nil, err
	}
	if len(res) == 0 {
		return false, nil, nil
	}
	edges, err := p.edgesOf(ctx, tenant)
	if err != nil {
		return false, nil, err
	}
	return true, edgesForPath(edges, res[0].Path), nil
}

// ShortestPath 最短路径边序列（不可达=空）。
func (p *PGPath) ShortestPath(ctx context.Context, tenant, from, to string) ([]graph.Relation, error) {
	ok, edges, err := p.Reachable(ctx, tenant, from, to, graph.DefaultMaxDepth)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return edges, nil
}

// Subgraph k 跳子图（递归 CTE 展开 + 实体/边回填）。
func (p *PGPath) Subgraph(ctx context.Context, tenant, fp string, depth int) ([]graph.Entity, []graph.Relation, error) {
	res, err := p.walkPaths(ctx, tenant, []string{fp}, nil, nil, depth)
	if err != nil {
		return nil, nil, err
	}
	inSet := map[string]bool{fp: true}
	for _, r := range res {
		for _, n := range r.Path {
			inSet[n] = true
		}
	}
	edges, err := p.edgesOf(ctx, tenant)
	if err != nil {
		return nil, nil, err
	}
	var outRels []graph.Relation
	for _, e := range edges {
		if inSet[e.FromFP] && inSet[e.ToFP] {
			outRels = append(outRels, e)
		}
	}
	kinds, err := p.kindsOf(ctx, tenant)
	if err != nil {
		return nil, nil, err
	}
	var outEnts []graph.Entity
	for n := range inSet {
		if k, ok := kinds[n]; ok {
			outEnts = append(outEnts, graph.Entity{Tenant: tenant, Fingerprint: n, Kind: k, InScope: true})
		}
	}
	sortEnts(outEnts)
	return outEnts, outRels, nil
}

// TopPaths 入口→高价值目标的最短路径 TopN（CTE 枚举 + 共用排序）。
func (p *PGPath) TopPaths(ctx context.Context, tenant string, limit int) ([]graph.Path, error) {
	res, err := p.walkPaths(ctx, tenant, nil, graph.EntryKinds, nil, graph.DefaultMaxDepth)
	if err != nil {
		return nil, err
	}
	kinds, err := p.kindsOf(ctx, tenant)
	if err != nil {
		return nil, err
	}
	edges, err := p.edgesOf(ctx, tenant)
	if err != nil {
		return nil, err
	}
	var paths []graph.Path
	for _, r := range res {
		if !isTargetKind(kinds[r.End]) {
			continue
		}
		er := edgesForPath(edges, r.Path)
		if len(er) == 0 {
			continue
		}
		paths = append(paths, graph.BuildPath(r.Start, kinds[r.Start], r.End, kinds[r.End], er))
	}
	return graph.RankPaths(paths, limit), nil
}

// isTargetKind 目标种类判定（与 graph.TargetKinds 同源）。
func isTargetKind(kind string) bool {
	for _, k := range graph.TargetKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// edgesForPath 把指纹序列还原为边序列（首条匹配边；缺失则该段无证据，返回已得部分）。
func edgesForPath(edges []graph.Relation, path []string) []graph.Relation {
	var out []graph.Relation
	for i := 0; i+1 < len(path); i++ {
		found := false
		for _, e := range edges {
			if e.FromFP == path[i] && e.ToFP == path[i+1] {
				out = append(out, e)
				found = true
				break
			}
		}
		if !found {
			return out // 边缺失=路径不可复现（不补造）
		}
	}
	return out
}

// sortEnts 复用 graph 包排序（排序口径单点：切后端顺序不漂移）。
func sortEnts(es []graph.Entity) { graph.SortEntities(es) }
