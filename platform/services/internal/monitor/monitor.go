// Package monitor 实现监测与预警（F14 / FR-MON-001~004，MVP 近似版）：
// 进程内定时 tick + 导入事件触发扫描（ENH-01 调度接管前的事实源近似的执行器）；
// 告警收敛=只推高危（漏洞 severity∈{critical,high}、IOC confidence≥0.8）+
// (kind,ref,asset) 幂等去重（无重复推送）+ 按置信度降序。
// FR-MON-002 增量 Diff / FR-MON-003 资产变更重扫以「漏洞匹配/情报命中」类告警近似，
// 图谱 diff 由 ENH-02 图 Provider 接管后完善（口径已在开发计划 §14.4 声明）。
package monitor

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/intel"
	"github.com/wangdev88/easm-platform/platform/services/internal/vuln"
)

var (
	ErrKind     = errors.New("monitor: kind 必须为 vuln|intel|both")
	ErrNotFound = errors.New("monitor: 监控器不存在")
)

// minIntelConf 高危情报收敛阈值（PRD F14.4「只推高危」口径）。
const minIntelConf = 0.8

type Alert struct {
	Key        string    `json:"key"`
	Kind       string    `json:"kind"` // vuln_match | intel_hit
	Ref        string    `json:"ref"`
	TenantID   string    `json:"tenant_id"`
	AssetID    string    `json:"asset_id"`
	AssetName  string    `json:"asset_name"`
	Severity   string    `json:"severity"`
	Confidence float64   `json:"confidence"`
	Msg        string    `json:"msg"`
	TS         time.Time `json:"ts"`
}

type Spec struct {
	ID       int           `json:"id"`
	Name     string        `json:"name"`
	Kind     string        `json:"kind"`
	Interval time.Duration `json:"interval_ns"`
}

type Run struct {
	TS      time.Time `json:"ts"`
	Trigger string    `json:"trigger"`
	New     int       `json:"new_alerts"`
}

type Service struct {
	mu       sync.Mutex
	vuln     *vuln.Service
	intel    *intel.Service
	provider func() map[string][]asset.Asset
	snap     SnapStore // FR-MON-002 diff 快照端口；nil=DiffScan 跳过（能力边界声明）
	alerts   []Alert
	keys     map[string]bool
	specs    map[int]*Spec
	history  map[int][]Run
	seq      int
	ctx      context.Context
}

func New(v *vuln.Service, i *intel.Service, provider func() map[string][]asset.Asset) *Service {
	return &Service{vuln: v, intel: i, provider: provider,
		keys: map[string]bool{}, specs: map[int]*Spec{}, history: map[int][]Run{}}
}

func validKind(k string) bool {
	return k == "vuln" || k == "intel" || k == "both" || k == "diff"
}

// Add 创建监控器；已 Start 则立即挂上调度（FR-MON-001 任务按配置周期执行）。
func (s *Service) Add(name, kind string, interval time.Duration) (Spec, error) {
	if !validKind(kind) {
		return Spec{}, ErrKind
	}
	s.mu.Lock()
	s.seq++
	sp := Spec{ID: s.seq, Name: name, Kind: kind, Interval: interval}
	s.specs[sp.ID] = &sp
	ctx := s.ctx
	s.mu.Unlock()
	if ctx != nil && interval > 0 {
		go s.loop(sp.ID, interval, ctx)
	}
	return sp, nil
}

func (s *Service) Get(id int) (Spec, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sp, ok := s.specs[id]
	if !ok {
		return Spec{}, ErrNotFound
	}
	return *sp, nil
}

func (s *Service) Specs() []Spec {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Spec, 0, len(s.specs))
	for _, sp := range s.specs {
		out = append(out, *sp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Service) History(id int) []Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Run(nil), s.history[id]...)
}

// Start 启动调度协程；ctx 取消即停表（MVP 进程内近似，ENH-01 接管）。
func (s *Service) Start(ctx context.Context) {
	s.mu.Lock()
	s.ctx = ctx
	var todo []Spec
	for _, sp := range s.specs {
		if sp.Interval > 0 {
			todo = append(todo, *sp)
		}
	}
	s.mu.Unlock()
	for _, sp := range todo {
		go s.loop(sp.ID, sp.Interval, ctx)
	}
}

func (s *Service) loop(id int, d time.Duration, ctx context.Context) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.scanAt("cron", id, "", s.provider())
		}
	}
}

// RunNow 用平台 provider 手动触发（测试/内置入口）。
func (s *Service) RunNow(id int) (int, error) { return s.RunVisible(id, s.provider()) }

// RunVisible 对指定可见面手动触发（REST /run：请求级主体作用域）。
func (s *Service) RunVisible(id int, visible map[string][]asset.Asset) (int, error) {
	sp, err := s.Get(id)
	if err != nil {
		return 0, err
	}
	return s.scanAt("manual", id, sp.Kind, visible), nil
}

// OnImport 事件驱动（FR-MON-001/003 近似）：新 CVE/IOC 入库即触发匹配扫描。
// kind=0 号伪监控器留痕（系统内置实时监测），history[0] 即事件流水。
func (s *Service) OnImport(kind string, visible map[string][]asset.Asset) int {
	return s.scanAt("import:"+kind, 0, kind, visible)
}

// scanAt 唯一告警生成入口。kind 空=both（按 spec）；重复 key 不产生新告警（FR-MON-004）。
func (s *Service) scanAt(trigger string, specID int, kind string, visible map[string][]asset.Asset) int {
	if kind == "" {
		s.mu.Lock()
		if sp, ok := s.specs[specID]; ok {
			kind = sp.Kind
		} else {
			kind = "both"
		}
		s.mu.Unlock()
	}
	newer := 0
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	all := []asset.Asset{}
	for _, list := range visible {
		all = append(all, list...)
	}
	if kind == "diff" { // FR-MON-002：增量 diff 独立实现（需 SnapStore），历史统一在此记
		s.mu.Unlock()
		n := s.DiffScan(context.Background(), visible)
		s.mu.Lock()
		s.history[specID] = append(s.history[specID], Run{TS: now, Trigger: trigger, New: n})
		return n
	}
	if kind == "vuln" || kind == "both" {
		for _, e := range s.vuln.List("", "") {
			if e.Severity != "critical" && e.Severity != "high" { // 只推高危
				continue
			}
			matches := vuln.MatchAssets(e, all)
			if len(matches) == 0 {
				continue
			}
			conf := vuln.Priority(e.CVSS, e.EPSS, len(matches)) / 100
			for _, a := range matches {
				key := fmt.Sprintf("vuln_match|%s|%s", e.CVE, a.ID)
				if s.keys[key] {
					continue
				}
				s.keys[key] = true
				s.alerts = append(s.alerts, Alert{Key: key, Kind: "vuln_match", Ref: e.CVE,
					TenantID: a.Tenant, AssetID: a.ID, AssetName: a.Name, Severity: e.Severity,
					Confidence: round2(conf), Msg: fmt.Sprintf("%s 命中资产 %s（标签 %v）", e.Title, a.Name, e.Tags), TS: now})
				newer++
			}
		}
	}
	if kind == "intel" || kind == "both" {
		for _, h := range s.intel.HitAssets(all) {
			if h.IOC.Confidence < minIntelConf {
				continue
			}
			key := fmt.Sprintf("intel_hit|%s|%s", h.IOC.Value, h.AssetID)
			if s.keys[key] {
				continue
			}
			s.keys[key] = true
			sev := "high"
			if h.IOC.Confidence >= 0.9 {
				sev = "critical"
			}
			s.alerts = append(s.alerts, Alert{Key: key, Kind: "intel_hit", Ref: h.IOC.Value,
				AssetID: h.AssetID, Severity: sev, Confidence: h.IOC.Confidence,
				Msg: fmt.Sprintf("情报 %s（%s）命中资产 %s：%s", h.IOC.Value, h.IOC.Threat, h.AssetID, h.Rule), TS: now})
			newer++
		}
	}
	s.history[specID] = append(s.history[specID], Run{TS: now, Trigger: trigger, New: newer})
	return newer
}

// List 告警流：置信度降序（同分按 key 稳定序）（FR-MON-004「按置信度排序」）。
func (s *Service) List(kind string) []Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Alert, 0, len(s.alerts))
	for _, a := range s.alerts {
		if kind != "" && a.Kind != kind {
			continue
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func round2(f float64) float64 { return float64(int(f*100+0.5)) / 100 }
