// Package ingest 把资产入账投影为 Exposure Graph 实体/关系（WP-M0-06 联动，FR-DSC-012），
// 并提供图谱读取端口供 IR-06 端点消费。asset 包不依赖 graph 包，投影在装配层注入。
package ingest

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
)

// ErrUnmappedType：MVP 未覆盖的资产类型不投影（避免弱指纹污染图谱）；
// 这些类型的图谱承接在 M1 工具容器化（parser 归一 Candidate）时落地。
var ErrUnmappedType = errors.New("ingest: asset type not mapped to graph yet")

// entityOf 返回资产主实体的 kind/props/额外 IP 实体与其到主实体的关系。
func entityOf(a asset.Asset) (main graph.Entity, ip *graph.Entity, ok bool) {
	kind, props := mapKind(a)
	if kind == "" {
		return graph.Entity{}, nil, false
	}
	now := a.Found
	if now.IsZero() {
		now = time.Now().UTC()
	}
	main = graph.Entity{
		Kind: kind, Tenant: a.Tenant, Props: props,
		FirstSeen: now, LastSeen: now, InScope: true,
		Sources: []string{firstNonEmpty(a.Source, "manual")},
	}
	// 域名/网站资产且带 IP → 追加 IP 实体与 resolves_to 边（暴露链最小可推演形态）
	if (kind == graph.KindDomain || kind == graph.KindWebApp) && strings.TrimSpace(a.IP) != "" {
		ipp := graph.Entity{
			Kind: graph.KindIPBlock, Tenant: a.Tenant,
			Props:     map[string]string{"cidr": a.IP + "/32"},
			FirstSeen: now, LastSeen: now, InScope: true,
			Sources: []string{firstNonEmpty(a.Source, "manual")},
		}
		return main, &ipp, true
	}
	return main, nil, true
}

func mapKind(a asset.Asset) (string, map[string]string) {
	switch a.Type {
	case "domain", "cert":
		return graph.KindDomain, map[string]string{"value": a.Name}
	case "web", "url":
		return graph.KindWebApp, map[string]string{"url": a.Name}
	case "ip":
		return graph.KindIPBlock, map[string]string{"cidr": a.Name}
	case "port":
		port := "0"
		if len(a.Ports) > 0 {
			port = itoa(a.Ports[0])
		}
		ip := a.IP
		if ip == "" {
			ip = a.Name
		}
		return graph.KindPort, map[string]string{"ip": ip, "port": port}
	case "repo":
		return graph.KindCodeRepo, map[string]string{"url": a.Name}
	case "credential":
		return graph.KindCredential, map[string]string{"type": "leaked", "value": a.Name}
	default:
		// cloud/doc/person/org → MVP 未映射
		return "", nil
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// Projector 用 graph.Service 完成幂等 upsert（merge 而非新增，FR-GPH-002）。
type Projector struct {
	gs *graph.Service
}

func NewProjector(gs *graph.Service) *Projector { return &Projector{gs: gs} }

// Sync 实现 asset.SyncFunc：把入账资产写入图谱。
func (p *Projector) Sync(ctx context.Context, a asset.Asset) error {
	main, ip, ok := entityOf(a)
	if !ok {
		return nil // 未映射类型：不投影，也不失败（M1 起由 parser 承接）
	}
	if _, _, err := p.gs.UpsertEntity(ctx, main); err != nil {
		return err
	}
	if ip != nil {
		if _, _, err := p.gs.UpsertEntity(ctx, *ip); err != nil {
			return err
		}
		rel := graph.Relation{
			Tenant: a.Tenant, Type: graph.RelResolvesTo,
			FromFP: graph.Fingerprint(main.Kind, main.Props),
			ToFP:   graph.Fingerprint(ip.Kind, ip.Props),
			TS:     main.LastSeen,
		}
		return p.gs.UpsertRelation(ctx, rel)
	}
	return nil
}

// Reader 是图谱读取端口（IR-06）；PGGraph 满足（FindByFingerprint + Neighbors）。
type Reader interface {
	FindByFingerprint(ctx context.Context, tenant, fp string) (graph.Entity, bool, error)
	Neighbors(ctx context.Context, tenant, fp string) ([]graph.Relation, error)
}

// QueryService 组合 graph.Service 与 Reader，供 httpapi 使用。
type QueryService struct {
	gs *graph.Service
	rd Reader
}

func NewQueryService(gs *graph.Service, rd Reader) *QueryService {
	return &QueryService{gs: gs, rd: rd}
}

func (q *QueryService) EntityByFingerprint(ctx context.Context, tenant, fp string) (graph.Entity, bool, error) {
	return q.rd.FindByFingerprint(ctx, tenant, fp)
}

func (q *QueryService) Neighbors(ctx context.Context, tenant, fp string) ([]graph.Relation, error) {
	return q.rd.Neighbors(ctx, tenant, fp)
}

// FingerprintForAsset 复用投影映射，保证「按资产查图谱」与「入账投影」同指纹口径。
func FingerprintForAsset(a asset.Asset) string {
	main, _, ok := entityOf(a)
	if !ok {
		return ""
	}
	return graph.Fingerprint(main.Kind, main.Props)
}
