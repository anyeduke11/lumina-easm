// diff.go — FR-MON-002 增量 Diff（本批销账：不再以「匹配类告警近似」）。
// 语义：与上次资产快照对比，输出 新增/变更/消失 三类 asset_diff 告警；
// 首跑只立基线；去重键含指纹（同状态重扫不重复推送，指纹变化才突破——FR-MON-004）。
// Diff 的「验收=与图谱变更一致」以 assets 表为入口事实源落地（图谱投影同源于入账，AX-1）。
package monitor

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
)

// SnapStore 资产快照端口（pgstore.SnapStore 满足；008_diff.sql）。
type SnapStore interface {
	LoadSnapshot(ctx context.Context, tenant string) (map[string]string, error)
	SaveSnapshot(ctx context.Context, tenant string, snap map[string]string) error
}

func (s *Service) SetSnapStore(st SnapStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snap = st
}

// fp 资产确定性指纹：影响 diff 判定的字段全集（增删字段=口径变更，须同步测试）。
func fp(a asset.Asset) string {
	return strings.Join([]string{a.Name, a.Risk, fmt.Sprint(a.Exp), a.Status, a.IP, strings.Join(a.Tags, ",")}, "\x1f")
}

// DiffScan 对比并回写快照；返回新增告警数。snap 未注入=静默跳过（能力边界由徽标/文档声明）。
func (s *Service) DiffScan(ctx context.Context, visible map[string][]asset.Asset) int {
	s.mu.Lock()
	st := s.snap
	s.mu.Unlock()
	if st == nil {
		return 0
	}
	tenants := make([]string, 0, len(visible))
	for t := range visible {
		tenants = append(tenants, t)
	}
	sort.Strings(tenants)
	newer := 0
	now := time.Now().UTC()
	for _, tid := range tenants {
		prev, err := st.LoadSnapshot(ctx, tid)
		if err != nil {
			continue // 单租户失败不炸全轮（下轮自然重试；fail loud 依赖告警计数为 0 的观测）
		}
		cur := map[string]string{}
		for _, a := range visible[tid] {
			cur[a.ID] = fp(a)
		}
		for _, a := range visible[tid] { // added / changed（按资产序稳定）
			f := cur[a.ID]
			p, existed := prev[a.ID]
			switch {
			case !existed && len(prev) > 0:
				s.addDiffAlert(&newer, "新增", a, a.Risk, f, now)
			case existed && p != f:
				s.addDiffAlert(&newer, "变更", a, a.Risk, f, now)
			}
		}
		ids := make([]string, 0, len(prev))
		for id := range prev {
			if _, ok := cur[id]; !ok {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		for _, id := range ids { // removed：等级 medium（不外发出口，留告警流审计）
			s.addDiffAlertByKey(&newer, "消失", tid, id, "medium", prev[id], now)
		}
		_ = st.SaveSnapshot(ctx, tid, cur) // 首跑亦落基线（added 闸：len(prev)>0 已挡）
	}
	return newer
}

func (s *Service) addDiffAlert(newer *int, verb string, a asset.Asset, sev, f string, now time.Time) {
	s.appendAlert(newer, Alert{
		Kind: "asset_diff", Ref: a.ID, TenantID: a.Tenant, AssetID: a.ID, AssetName: a.Name,
		Severity: sev, Confidence: 1.0, TS: now,
		Msg: fmt.Sprintf("资产%s：%s（指纹 %s）", verb, a.Name, shortHash(f)),
	}, diffKey(verb, a.ID, f))
}

func (s *Service) addDiffAlertByKey(newer *int, verb, tid, id, sev, f string, now time.Time) {
	s.appendAlert(newer, Alert{
		Kind: "asset_diff", Ref: id, TenantID: tid, AssetID: id,
		Severity: sev, Confidence: 1.0, TS: now,
		Msg: fmt.Sprintf("资产%s：%s（末次指纹 %s）", verb, id, shortHash(f)),
	}, diffKey(verb, id, f))
}

func (s *Service) appendAlert(newer *int, a Alert, key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys[key] {
		return
	}
	s.keys[key] = true
	a.Key = key
	s.alerts = append(s.alerts, a)
	*newer++
}

// diffKey：verb|assetID|指纹 —— 同状态重扫去重，指纹变化（如 Exp 60→95→100）逐次突破。
func diffKey(verb, id, f string) string { return "asset_diff|" + verb + "|" + id + "|" + shortHash(f) }

func shortHash(s string) string {
	// FNV 简化 8hex 摘要（确定性；避免告警流塞长指纹）
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("%016x", h)[:12]
}
