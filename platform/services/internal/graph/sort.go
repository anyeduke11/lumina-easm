package graph

// 确定性排序助手（M3-B）：内存 store 与 PG 侧 ORDER BY 需产出同一顺序，
// 否则双后端 TopN 会漂移（AX-3 可复现）。

import "sort"

// SortRelations 按 (from_fp, to_fp, type) 排序（导出=PG 侧共用，排序口径单点）。
func SortRelations(rs []Relation) { sortRelations(rs) }

// SortEntities 按 fingerprint 排序（导出=PG 侧共用，排序口径单点）。
func SortEntities(es []Entity) { sortEntities(es) }

// sortRelations 按 (from_fp, to_fp, type) 排序。
func sortRelations(rs []Relation) {
	sort.Slice(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if a.FromFP != b.FromFP {
			return a.FromFP < b.FromFP
		}
		if a.ToFP != b.ToFP {
			return a.ToFP < b.ToFP
		}
		return a.Type < b.Type
	})
}

// sortEntities 按 fingerprint 排序。
func sortEntities(es []Entity) {
	sort.Slice(es, func(i, j int) bool { return es[i].Fingerprint < es[j].Fingerprint })
}
