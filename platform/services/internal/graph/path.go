package graph

// 攻击路径推演端口与内存实现（M3-B / FR-GPH-004 / WP-M3-01 重基线）。
//
// 编号：FR-GPH-004 多跳攻击路径推演、FR-MIN-001/002（M3-A 评分为路径排序提供目标权重）、
// ENH-02（Neo4j Provider 同一端口替换）、AX-2 确定性、AX-3 可解释。
//
// 双实现契约（接缝不变、Provider 替换）：
//   - MemPath（本文件）：Go 内 BFS，供内存模式与单测；
//   - pgstore.PGPath：PG 递归 CTE，供 PG 模式；
//   - 同一图在两种实现下必须给出**同一 TopN**（排序函数在 graph 包共享，集成测试对账）。
//
// 排名口径（确定性，无随机/时间项）：跳数升序 → 目标种类优先级（凭证 > 业务资产 > 代码仓库 >
// 云资源）→ 起点指纹字典序 → 终点指纹字典序。

import (
	"context"
	"errors"
	"sort"
)

// 默认深度上限（防爆炸；路径推演受控）。
const (
	DefaultMaxDepth = 6
	DefaultTopN     = 5
)

var (
	// EntryKinds 入口实体种类（暴露面起点）。
	EntryKinds = []string{KindDomain, KindIPBlock, KindPort}
	// TargetKinds 高价值目标实体种类（攻击路径终点）。
	TargetKinds = []string{KindCredential, KindBusinessAsset, KindCodeRepo, KindCloudResource}
)

// Path 一条攻击路径（可复现：节点序列 + 边序列；可处置：缓解建议 + 理由）。
type Path struct {
	FromFP      string     `json:"from_fp"`
	ToFP        string     `json:"to_fp"`
	ToKind      string     `json:"to_kind"` // 目标实体种类（排序优先级依据，可解释）
	FromKind    string     `json:"from_kind"`
	Hops        int        `json:"hops"`
	Nodes       []string   `json:"nodes"`       // 指纹序列（含首尾）
	Edges       []Relation `json:"edges"`       // 边序列（与 Nodes 一一对应）
	Mitigations []string   `json:"mitigations"` // 按边类型给出的缓解建议
	Rationale   string     `json:"rationale"`   // 入选理由（可解释）
}

// PathQuery 攻击路径推演端口（MemPath / PGPath / 未来 Neo4j Provider 均实现）。
type PathQuery interface {
	// Reachable 深度受限可达性（返回实际路径边序列；不可达=ok=false, edges=nil）。
	Reachable(ctx context.Context, tenant, from, to string, maxDepth int) (bool, []Relation, error)
	// ShortestPath 最短路径（边序列；不可达=空切片，不报错）。
	ShortestPath(ctx context.Context, tenant, from, to string) ([]Relation, error)
	// Subgraph k 跳子图（实体+边）。
	Subgraph(ctx context.Context, tenant, fp string, depth int) ([]Entity, []Relation, error)
	// TopPaths Top N 攻击路径（确定性排序）。
	TopPaths(ctx context.Context, tenant string, limit int) ([]Path, error)
}

// Source 路径推演所需最小读取面（内存 store 与 PG store 均满足）。
type Source interface {
	Relations(ctx context.Context, tenant string) ([]Relation, error)
	Entities(ctx context.Context, tenant string) ([]Entity, error)
}

// MemPath Go 内 BFS 实现（确定性；多源 BFS 枚举入口→目标路径）。
type MemPath struct{ src Source }

// NewMemPath 构造内存路径推演（src 不可为空）。
func NewMemPath(src Source) *MemPath { return &MemPath{src: src} }

type edge struct {
	rel Relation
	to  string
}

// adjacency 邻接表（同 (from,to) 多关系时按 rel 类型+终点排序，保证确定性）。
func adjacency(rels []Relation) map[string][]edge {
	byKey := map[string]Relation{}
	for _, r := range rels {
		k := r.FromFP + "|" + r.ToFP + "|" + r.Type
		byKey[k] = r
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	adj := map[string][]edge{}
	for _, k := range keys {
		r := byKey[k]
		adj[r.FromFP] = append(adj[r.FromFP], edge{rel: r, to: r.ToFP})
	}
	return adj
}

// Reachable 深度受限 BFS。
func (m *MemPath) Reachable(ctx context.Context, tenant, from, to string, maxDepth int) (bool, []Relation, error) {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	rels, err := m.src.Relations(ctx, tenant)
	if err != nil {
		return false, nil, err
	}
	adj := adjacency(rels)
	// BFS：队列存 (节点, 路径边序列)
	type node struct {
		fp    string
		edges []Relation
		depth int
	}
	q := []node{{fp: from, edges: nil, depth: 0}}
	seen := map[string]bool{from: true}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		if cur.fp == to && len(cur.edges) > 0 {
			return true, cur.edges, nil
		}
		if cur.depth >= maxDepth {
			continue
		}
		for _, e := range adj[cur.fp] {
			if seen[e.to] {
				continue
			}
			seen[e.to] = true
			q = append(q, node{fp: e.to, edges: append(append([]Relation{}, cur.edges...), e.rel), depth: cur.depth + 1})
		}
	}
	return false, nil, nil
}

// ShortestPath 最短路径（BFS 首次命中即最短；同长度按字典序确定）。
func (m *MemPath) ShortestPath(ctx context.Context, tenant, from, to string) ([]Relation, error) {
	ok, edges, err := m.Reachable(ctx, tenant, from, to, DefaultMaxDepth)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return edges, nil
}

// Subgraph k 跳子图（BFS 收集实体与边）。
func (m *MemPath) Subgraph(ctx context.Context, tenant, fp string, depth int) ([]Entity, []Relation, error) {
	if depth <= 0 {
		depth = 1
	}
	ents, err := m.src.Entities(ctx, tenant)
	if err != nil {
		return nil, nil, err
	}
	rels, err := m.src.Relations(ctx, tenant)
	if err != nil {
		return nil, nil, err
	}
	adj := adjacency(rels)
	inSet := map[string]bool{fp: true}
	frontier := []string{fp}
	var outRels []Relation
	for d := 0; d < depth && len(frontier) > 0; d++ {
		var next []string
		for _, cur := range frontier {
			for _, e := range adj[cur] {
				outRels = append(outRels, e.rel)
				if !inSet[e.to] {
					inSet[e.to] = true
					next = append(next, e.to)
				}
			}
		}
		frontier = next
	}
	var outEnts []Entity
	for _, e := range ents {
		if inSet[e.Fingerprint] {
			outEnts = append(outEnts, e)
		}
	}
	return outEnts, outRels, nil
}

// TopPaths 多源 BFS：从入口实体出发到高价值目标的最短路径，确定性排序取 TopN。
func (m *MemPath) TopPaths(ctx context.Context, tenant string, limit int) ([]Path, error) {
	if limit <= 0 {
		limit = DefaultTopN
	}
	ents, err := m.src.Entities(ctx, tenant)
	if err != nil {
		return nil, err
	}
	rels, err := m.src.Relations(ctx, tenant)
	if err != nil {
		return nil, err
	}
	kindOf := map[string]string{}
	for _, e := range ents {
		kindOf[e.Fingerprint] = e.Kind
	}
	isKind := func(fp string, kinds []string) bool {
		for _, k := range kinds {
			if kindOf[fp] == k {
				return true
			}
		}
		return false
	}
	adj := adjacency(rels)
	var out []Path
	for _, from := range sortedFingerprints(ents, func(fp string) bool { return isKind(fp, EntryKinds) }) {
		// 单源 BFS 记录最短边序列
		type node struct {
			fp    string
			edges []Relation
			depth int
		}
		q := []node{{fp: from, edges: nil, depth: 0}}
		seen := map[string]bool{from: true}
		for len(q) > 0 {
			cur := q[0]
			q = q[1:]
			if cur.depth >= DefaultMaxDepth {
				continue
			}
			for _, e := range adj[cur.fp] {
				if seen[e.to] {
					continue
				}
				seen[e.to] = true
				edges := append(append([]Relation{}, cur.edges...), e.rel)
				if isKind(e.to, TargetKinds) {
					out = append(out, BuildPath(from, kindOf[from], e.to, kindOf[e.to], edges))
				}
				q = append(q, node{fp: e.to, edges: edges, depth: cur.depth + 1})
			}
		}
	}
	return RankPaths(out, limit), nil
}

// sortedFingerprints 按指纹字典序取满足条件的实体（确定性枚举顺序）。
func sortedFingerprints(ents []Entity, keep func(fp string) bool) []string {
	var out []string
	for _, e := range ents {
		if keep(e.Fingerprint) {
			out = append(out, e.Fingerprint)
		}
	}
	sort.Strings(out)
	return out
}

// buildPath 由边序列构造路径（节点序列 + 缓解建议 + 理由）。
func BuildPath(from, fromKind, to, toKind string, edges []Relation) Path {
	nodes := []string{from}
	mit := make([]string, 0, len(edges))
	for _, e := range edges {
		nodes = append(nodes, e.ToFP)
		mit = append(mit, Mitigation(e.Type))
	}
	return Path{FromFP: from, FromKind: fromKind, ToFP: to, ToKind: toKind,
		Hops: len(edges), Nodes: nodes, Edges: edges, Mitigations: mit,
		Rationale: "入口实体（" + fromKind + "）经 " + itoa(len(edges)) + " 跳可达高价值目标（" +
			toKind + "），最短路径，边序可复现"}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// RankPaths 确定性排序（双后端共用，保证 MemPath/PGPath 契约一致）：
// 同 (起点,终点) 只保留最短；再按 跳数→目标优先级→起点→终点 排序取 TopN。
func RankPaths(paths []Path, limit int) []Path {
	best := map[string]Path{}
	for _, p := range paths {
		k := p.FromFP + "|" + p.ToFP
		if cur, ok := best[k]; !ok || p.Hops < cur.Hops {
			best[k] = p
		}
	}
	out := make([]Path, 0, len(best))
	for _, p := range best {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Hops != b.Hops {
			return a.Hops < b.Hops
		}
		pa, pb := targetPriority(a.ToKind), targetPriority(b.ToKind)
		if pa != pb {
			return pa < pb
		}
		if a.FromFP != b.FromFP {
			return a.FromFP < b.FromFP
		}
		return a.ToFP < b.ToFP
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// targetPriority 目标种类优先级（凭证 > 业务资产 > 代码仓库 > 云资源；其余末位）。
func targetPriority(kind string) int {
	switch kind {
	case KindCredential:
		return 0
	case KindBusinessAsset:
		return 1
	case KindCodeRepo:
		return 2
	case KindCloudResource:
		return 3
	default:
		return 9
	}
}

// Mitigation 按关系类型给出缓解建议（可处置面；不为空文案）。
func Mitigation(rel string) string {
	switch rel {
	case RelOwns:
		return "确认资产归属，纳入台账并指定负责人"
	case RelResolvesTo:
		return "收敛解析记录，下线无用域名解析"
	case RelHosts:
		return "限制主机暴露面，仅开放必要网段"
	case RelServes:
		return "关闭非必要端口/服务，前置访问控制"
	case RelUses:
		return "核查依赖组件与凭据引用，最小化权限"
	case RelAffects:
		return "按漏洞优先级修复并回归复测"
	case RelLeaks:
		return "吊销并轮换泄露凭据，清理历史提交"
	case RelValidOn:
		return "立即轮换有效凭据并加访问控制"
	case RelReachable:
		return "收敛可达性（网络策略/白名单）"
	case RelDependsOn:
		return "梳理依赖关系，隔离关键资产"
	case RelObserved:
		return "核查观测来源，补证据并留痕"
	default:
		return "核查该关系来源并评估处置"
	}
}

// ErrPathUnavailable 路径推演未装配（端点侧映射 501，诚实边界不伪造路径）。
var ErrPathUnavailable = errors.New("graph: 路径推演未装配")
