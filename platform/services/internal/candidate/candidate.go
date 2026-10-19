// Package candidate 实现统一候选契约 `easm.candidate.v1`（WP-M1-05 契约部分 / M2-01/02 硬前置）：
// 工具与渠道产物经 parser 归一为本结构后进图谱/台账；校验失败/越权的原始行进
// unsupported 待处理队列（设计方案 §5.2：不污染台账、不静默丢弃——可复核，fail loud）。
// V-4：unsupported 队列可落 PG（Store 端口 + AttachStore 水化/写穿，014_review_queue.sql）——
// 复核锚点不得随进程蒸发（与 sweeps/authz/workorders/notices/darkweb/reports 同口径）。
// V-9：accepted 摄取留痕同样落 PG（AcceptedStore + AttachAcceptedStore，016）——
// 「摄取过什么」是可审计事实（工具适配层投喂历史），重启后不得只余计数不留记录。
package candidate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

// Evidence 证据引用（C-5：raw_ref 可回溯原始产物）。
type Evidence struct {
	URL         string `json:"url,omitempty"`
	SnapshotRef string `json:"snapshot_ref,omitempty"`
	TS          string `json:"ts"`
	RawRef      string `json:"raw_ref,omitempty"`
}

type Asset struct {
	Type    string         `json:"type"`
	Value   string         `json:"value"`
	Port    int            `json:"port,omitempty"`
	Service string         `json:"service,omitempty"`
	State   string         `json:"state,omitempty"`
	Extra   map[string]any `json:"extra,omitempty"`
}

type Finding struct {
	Title    string `json:"title,omitempty"`
	Category string `json:"category,omitempty"`
	Risk     string `json:"risk,omitempty"`
	Fix      string `json:"fix,omitempty"`
}

// Candidate = easm.candidate.v1（设计方案 §5.2 JSON Schema 对齐）。
type Candidate struct {
	Kind     string         `json:"kind"` // asset|finding|lead
	TenantID string         `json:"tenant_id"`
	SubCode  string         `json:"sub_code"`
	Channel  string         `json:"channel"`
	Asset    *Asset         `json:"asset,omitempty"`
	Finding  *Finding       `json:"finding,omitempty"`
	Lead     map[string]any `json:"lead,omitempty"`
	Evidence Evidence       `json:"evidence"`
}

// JSON 单行序列化（JSONL 摄取/回传形态）。
func (c Candidate) JSON() ([]byte, error) { return json.Marshal(c) }

var (
	kinds   = map[string]bool{"asset": true, "finding": true, "lead": true}
	atypes  = map[string]bool{"domain": true, "ip": true, "port": true, "web": true, "cert": true, "credential": true, "doc": true, "repo": true, "cloud": true, "person": true, "org": true}
	asates  = map[string]bool{"": true, "in_use": true, "idle": true, "abandoned": true, "pending": true, "excluded": true}
	cats    = map[string]bool{"": true, "系统架构类": true, "代码密码类": true, "业务经营类": true, "线索类": true}
	risks   = map[string]bool{"": true, "严重": true, "高": true, "中": true, "低": true}
	ErrKind = errors.New("candidate: kind 必须为 asset|finding|lead")
)

// Validate schema 必填集（kind/tenant_id/sub_code/channel/evidence.ts）+ 枚举 +
// kind 与载荷一致性（kind=finding 必带 finding 等——防「空壳候选」混入）。
func (c Candidate) Validate() error {
	miss := []string{}
	if c.Kind == "" {
		miss = append(miss, "kind")
	}
	if c.TenantID == "" {
		miss = append(miss, "tenant_id")
	}
	if c.SubCode == "" {
		miss = append(miss, "sub_code")
	}
	if c.Channel == "" {
		miss = append(miss, "channel")
	}
	if c.Evidence.TS == "" {
		miss = append(miss, "evidence.ts")
	}
	if len(miss) > 0 {
		return fmt.Errorf("candidate: 必填缺失 %s", strings.Join(miss, ","))
	}
	if !kinds[c.Kind] {
		return fmt.Errorf("%w: %q", ErrKind, c.Kind)
	}
	if _, err := time.Parse(time.RFC3339, c.Evidence.TS); err != nil {
		return errors.New("candidate: evidence.ts 必须为 RFC3339")
	}
	switch c.Kind {
	case "asset":
		if c.Asset == nil {
			return errors.New("candidate: kind=asset 必须带 asset 载荷")
		}
	case "finding":
		if c.Finding == nil {
			return errors.New("candidate: kind=finding 必须带 finding 载荷")
		}
	case "lead":
		if len(c.Lead) == 0 {
			return errors.New("candidate: kind=lead 必须带 lead 载荷")
		}
	}
	if c.Asset != nil {
		if c.Asset.Type == "" || c.Asset.Value == "" {
			return errors.New("candidate: asset.type/value 必填")
		}
		if !atypes[c.Asset.Type] {
			return fmt.Errorf("candidate: 非法 asset.type %q", c.Asset.Type)
		}
		if !asates[c.Asset.State] {
			return fmt.Errorf("candidate: 非法 asset.state %q", c.Asset.State)
		}
	}
	if c.Finding != nil {
		if !cats[c.Finding.Category] {
			return fmt.Errorf("candidate: 非法 finding.category %q", c.Finding.Category)
		}
		if !risks[c.Finding.Risk] {
			return fmt.Errorf("candidate: 非法 finding.risk %q", c.Finding.Risk)
		}
	}
	return nil
}

// Unsupported 待处理行：原始行+拒绝原因（复核锚点，禁止只存错误丢原文）。
type Unsupported struct {
	TS      time.Time `json:"ts"`
	Line    string    `json:"line"`
	Error   string    `json:"error"`
	Channel string    `json:"channel,omitempty"`
}

// Store unsupported 复核队列持久化端口（V-4 / 014_review_queue.sql；C-6 同契约）。
// Key 由 (line,error) 派生：重放/重试不重复入队（摄取是幂等友好的）。
type Store interface {
	Save(ctx context.Context, u Unsupported) error
	List(ctx context.Context) ([]Unsupported, error)
}

// AcceptedRecord 已接受候选的摄取留痕（V-9 / 016_candidate_accepted.sql）。
// 与内存候选队列分工：`accepted []Candidate` 是 collect 的进程内消费面；
// 本结构是持久审计面——带原始行（C-5 回溯）、摄取时刻与去重键。
type AcceptedRecord struct {
	Key        string    `json:"key"` // sha256(原始行)=摄取幂等键
	TenantID   string    `json:"tenant_id"`
	Kind       string    `json:"kind"`
	SubCode    string    `json:"sub_code"`
	Channel    string    `json:"channel"`
	TS         time.Time `json:"ts"`          // evidence.ts（候选自带）
	AcceptedAt time.Time `json:"accepted_at"` // 摄取时刻
	Line       string    `json:"line"`        // 原始 JSONL 行（回溯锚点）
}

// AcceptedStore accepted 摄取留痕持久化端口（V-9；C-6 同契约）。
// 方法名与 Store（unsupported）区分：同一 PG 结构同时实现两个端口，
// 签名不同不能同名（Go 接口约束），故以 Save/List 前缀消歧。
type AcceptedStore interface {
	SaveAccepted(ctx context.Context, a AcceptedRecord) error
	ListAccepted(ctx context.Context, tenant string) ([]AcceptedRecord, error)
}

// AcceptedKey 摄取幂等键：同一条原始行重复摄取=同一留痕（重放/重试不翻倍）。
func AcceptedKey(line string) string {
	sum := sha256.Sum256([]byte(line))
	return hex.EncodeToString(sum[:])
}

// UnsupportedKey 去重键（同原文同原因=同一复核项；跨重启稳定）。
func UnsupportedKey(line, reason string) string {
	sum := sha256.Sum256([]byte(line + "\x1f" + reason))
	return hex.EncodeToString(sum[:])
}

type Service struct {
	mu           sync.Mutex
	accepted     []Candidate
	acceptedRecs []AcceptedRecord // 持久留痕镜像（PG 模式=库的水化副本）
	unsupported  []Unsupported
	store        Store         // nil=纯内存（无 PG 的 dev/单测形态）
	accStore     AcceptedStore // nil=摄取留痕不落库
}

func NewService() *Service { return &Service{} }

// AttachStore 装载持久化端口并从库水化既有复核项（启动装配=复核锚点跨重启不丢；
// List 失败上浮拒绝半装配——宁可不带历史队列运行并 fail loud，不带错误镜像运行）。
func (s *Service) AttachStore(ctx context.Context, st Store) error {
	rows, err := st.List(ctx)
	if err != nil {
		return fmt.Errorf("candidate: unsupported 队列水化失败: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unsupported = append(s.unsupported, rows...)
	s.store = st
	return nil
}

// AttachAcceptedStore 装载摄取留痕端口并从库水化（V-9；与 AttachStore 同 fail-loud 口径：
// 水化失败拒绝半装配——「留着一半历史运行」比不带历史更危险）。
func (s *Service) AttachAcceptedStore(ctx context.Context, st AcceptedStore) error {
	// 水化范围=全租户（摄取端点按主体作用域过滤在 httpapi 层做，与服务内存镜像同口径）。
	rows, err := st.ListAccepted(ctx, "")
	if err != nil {
		return fmt.Errorf("candidate: accepted 留痕水化失败: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acceptedRecs = append(s.acceptedRecs, rows...)
	s.accStore = st
	return nil
}

// Ingest JSONL 逐行摄取：解析失败/校验失败/越权租户 → unsupported；合法 → 队列。
// 返回 (accepted, unsupported, err)；err 仅在服务级故障时非 nil（行级失败不是错误，
// 但行级拒绝原因**落库失败**是错误——复核锚点丢失不得静默）。
func (s *Service) Ingest(ctx context.Context, p rbac.Principal, jsonl string) (int, int, error) {
	acc, uns := 0, 0
	for _, line := range strings.Split(jsonl, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var c Candidate
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			if err := s.push(ctx, line, "JSON 解析失败: "+err.Error(), ""); err != nil {
				return acc, uns, err
			}
			uns++
			continue
		}
		ch := c.Channel
		if err := c.Validate(); err != nil {
			if err := s.push(ctx, line, err.Error(), ch); err != nil {
				return acc, uns, err
			}
			uns++
			continue
		}
		if !p.InScope(c.TenantID) { // 行级租户闸（与资产入账同口径，越权不入账）
			if err := s.push(ctx, line, "越权租户 "+c.TenantID, ch); err != nil {
				return acc, uns, err
			}
			uns++
			continue
		}
		if err := s.accept(ctx, line, c); err != nil {
			return acc, uns, err
		}
		acc++
	}
	return acc, uns, nil
}

// accept 记录已接受候选：先写穿留痕（装配了 AcceptedStore 时）再入内存队列——
// 留痕落库失败即上浮（摄取历史不完整不得静默，与 push 同口径 fail loud）。
// 幂等：同原始行重复摄取=同一留痕键，不翻倍（工具重放/重试友好）。
func (s *Service) accept(ctx context.Context, line string, c Candidate) error {
	key := AcceptedKey(line)
	s.mu.Lock()
	for _, r := range s.acceptedRecs {
		if r.Key == key {
			s.mu.Unlock()
			return nil // 已摄取过（含本次进程早前/重启前）：留痕与队列均不重复
		}
	}
	s.mu.Unlock()
	ts, _ := time.Parse(time.RFC3339, c.Evidence.TS) // Validate 已保证可解析
	rec := AcceptedRecord{
		Key: key, TenantID: c.TenantID, Kind: c.Kind, SubCode: c.SubCode,
		Channel: c.Channel, TS: ts, AcceptedAt: time.Now().UTC(), Line: line,
	}
	s.mu.Lock()
	st := s.accStore
	s.mu.Unlock()
	if st != nil {
		if err := st.SaveAccepted(ctx, rec); err != nil {
			return fmt.Errorf("candidate: accepted 留痕落库失败: %w", err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acceptedRecs = append(s.acceptedRecs, rec)
	s.accepted = append(s.accepted, c)
	return nil
}

// push 记录拒绝行：先写穿（装配了 Store 时）再入内存镜像——库失败即上浮，
// 调用方可见 500；宁可以本次摄取失败换取「复核锚点不丢」（fail loud）。
// 内存镜像与库一致：库按 (line,error) 去重，镜像同样不得重复追加
// （否则重启前后复核面计数漂移=双份数据源不一致）。
func (s *Service) push(ctx context.Context, line, reason, ch string) error {
	u := Unsupported{TS: time.Now().UTC(), Line: line, Error: reason, Channel: ch}
	key := UnsupportedKey(line, reason)
	s.mu.Lock()
	st := s.store
	for _, e := range s.unsupported {
		if UnsupportedKey(e.Line, e.Error) == key {
			s.mu.Unlock()
			return nil // 已入队（含本次进程早前摄取）：镜像不重复
		}
	}
	s.mu.Unlock()
	if st != nil {
		if err := st.Save(ctx, u); err != nil {
			return fmt.Errorf("candidate: unsupported 落库失败: %w", err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unsupported = append(s.unsupported, u)
	return nil
}

func (s *Service) List() []Candidate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Candidate(nil), s.accepted...)
}

func (s *Service) Unsupported() []Unsupported {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Unsupported(nil), s.unsupported...)
}

// Accepted 摄取留痕（V-9）。tenant 为空=全量（调用方负责按主体作用域过滤，
// 与内存候选队列的跨租户可见性口径一致：服务层不做 RBAC，闸在 httpapi）。
func (s *Service) Accepted(tenant string) []AcceptedRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []AcceptedRecord{}
	for _, r := range s.acceptedRecs {
		if tenant == "" || r.TenantID == tenant {
			out = append(out, r)
		}
	}
	return out
}
