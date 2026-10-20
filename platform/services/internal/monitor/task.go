// task.go — FR-MON-003 排查任务单（M4-03 销账）。
// 语义：资产新增/变更（diff 触发）或新 POC/CVE 发布 → 生成排查任务单（RT-<sha12>）；
// 验收「触发后生成对应排查任务」=任务单可查询、可完成（人工确认=AX-5）、闭环后可再触发。
// 幂等：同租户同资产同触发源存在 pending 单=不重复开单（ID 含时间戳，闭环后重开是新单）。
// 持久化：未装配 PG=进程内 MemTaskStore；AttachTaskStore 后 PG 为单一事实源
// （跨重启可查，与 notify_log 同口径；不双写=防内存/PG 分叉）。
package monitor

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

	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
)

// 触发源与状态（枚举固定）。
const (
	TriggerDiffNew     = "diff_new"     // 资产新增
	TriggerDiffChanged = "diff_changed" // 资产变更（指纹变化）
	TriggerNewPOC      = "new_poc"      // 新 POC/CVE 发布

	TaskPending = "pending"
	TaskDone    = "done"
)

// tenantLevelAssetID 租户级任务单（POC 影响面未指明=全租户重扫）。
const tenantLevelAssetID = "*"

// Task 排查任务单。
type Task struct {
	ID        string     `json:"id"`
	Tenant    string     `json:"tenant"`
	AssetID   string     `json:"asset_id"` // 租户级=*
	AssetName string     `json:"asset_name,omitempty"`
	Trigger   string     `json:"trigger"`
	Reason    string     `json:"reason"`
	Status    string     `json:"status"`
	By        string     `json:"by,omitempty"`   // 完成人
	Note      string     `json:"note,omitempty"` // 完成说明
	CreatedAt time.Time  `json:"created_at"`
	DoneAt    *time.Time `json:"done_at,omitempty"`
}

var (
	ErrTaskNotFound = errors.New("monitor: 任务单不存在")
	ErrTaskClosed   = errors.New("monitor: 任务单已闭环（终态，不得重复虚报）")
	// ErrTaskInvalid 请求不合法（缺完成人/缺租户资产等；httpapi 映射 400）。
	ErrTaskInvalid = errors.New("monitor: 非法请求")
)

// TaskStore 任务单端口（pgstore.MonitorTaskStore 满足）。
type TaskStore interface {
	AddTask(ctx context.Context, tk Task) (created bool, err error)
	ListTasks(ctx context.Context, tenant, status string) ([]Task, error)
	DoneTask(ctx context.Context, tenant, id, by, note string) (Task, error)
}

// MemTaskStore 内存实现（未装配 PG 的回退；双后端同契约）。
type MemTaskStore struct {
	mu    sync.Mutex
	tasks []Task
}

func NewMemTaskStore() *MemTaskStore { return &MemTaskStore{} }

func (m *MemTaskStore) AddTask(_ context.Context, tk Task) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, t := range m.tasks {
		if t.Tenant == tk.Tenant && t.AssetID == tk.AssetID && t.Trigger == tk.Trigger &&
			t.Status == TaskPending {
			// 同源 pending 单收敛刷新（理由与触发时间更新、ID 保留）——不堆叠多张
			// 未闭环的单（告警收敛同口径；已完成=新事实，走新单）。
			m.tasks[i].Reason = tk.Reason
			m.tasks[i].AssetName = tk.AssetName
			m.tasks[i].CreatedAt = tk.CreatedAt
			return false, nil
		}
	}
	m.tasks = append(m.tasks, tk)
	return true, nil
}

func (m *MemTaskStore) ListTasks(_ context.Context, tenant, status string) ([]Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Task, 0, len(m.tasks))
	for _, t := range m.tasks {
		if t.Tenant == tenant && (status == "" || t.Status == status) {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

func (m *MemTaskStore) DoneTask(_ context.Context, tenant, id, by, note string) (Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, t := range m.tasks {
		if t.ID == id && t.Tenant == tenant {
			if t.Status == TaskDone {
				return t, ErrTaskClosed
			}
			now := time.Now().UTC()
			m.tasks[i].Status = TaskDone
			m.tasks[i].By, m.tasks[i].Note = by, note
			m.tasks[i].DoneAt = &now
			return m.tasks[i], nil
		}
	}
	return Task{}, ErrTaskNotFound
}

// AttachTaskStore 装配 PG 任务单存储（装配后 PG 为单一事实源；未装配=进程内）。
func (s *Service) AttachTaskStore(st TaskStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.taskStore = st
}

func (s *Service) taskStoreRef() TaskStore {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.taskStore != nil {
		return s.taskStore
	}
	if s.taskMem == nil {
		s.taskMem = NewMemTaskStore()
	}
	return s.taskMem
}

// EnqueueRescan 生成排查任务单（幂等：pending 同源单已存在则不重复）。
func (s *Service) EnqueueRescan(ctx context.Context, tenant, assetID, assetName, trigger, reason string) error {
	if strings.TrimSpace(tenant) == "" || strings.TrimSpace(assetID) == "" {
		return fmt.Errorf("%w: 任务单租户与资产必填", ErrTaskInvalid)
	}
	now := time.Now().UTC()
	tk := Task{
		ID: taskID(tenant, assetID, trigger, now), Tenant: tenant, AssetID: assetID,
		AssetName: assetName, Trigger: trigger, Reason: reason,
		Status: TaskPending, CreatedAt: now,
	}
	created, err := s.taskStoreRef().AddTask(ctx, tk)
	if err != nil {
		return fmt.Errorf("monitor: 任务单落库失败: %w", err)
	}
	_ = created // created=false=同源 pending 单已存在（幂等命中，如实不开单）
	return nil
}

// OnNewPOC 新 POC/CVE 发布 → 受影响资产（或租户级）排查任务单（FR-MON-003）。
func (s *Service) OnNewPOC(ctx context.Context, tenant, cveID string, affected []asset.Asset) error {
	if strings.TrimSpace(cveID) == "" {
		return fmt.Errorf("%w: CVE/POC 编号必填", ErrTaskInvalid)
	}
	if len(affected) == 0 {
		return s.EnqueueRescan(ctx, tenant, tenantLevelAssetID, tenant,
			TriggerNewPOC, "新 POC/CVE 发布："+cveID+"（影响面未指明=全租户重扫）")
	}
	for _, a := range affected {
		if err := s.EnqueueRescan(ctx, tenant, a.ID, a.Name,
			TriggerNewPOC, "新 POC/CVE 发布："+cveID); err != nil {
			return err
		}
	}
	return nil
}

// Tasks 查询任务单（PG 优先为事实源；未装配=进程内）。
func (s *Service) Tasks(ctx context.Context, tenant, status string) ([]Task, error) {
	return s.taskStoreRef().ListTasks(ctx, tenant, status)
}

// TaskDone 完成任务单（人工确认执行=AX-5；终态不得重复闭环）。
func (s *Service) TaskDone(ctx context.Context, tenant, id, by, note string) (Task, error) {
	if strings.TrimSpace(by) == "" {
		return Task{}, fmt.Errorf("%w: 完成人必填（人在环，闭环可追溯）", ErrTaskInvalid)
	}
	return s.taskStoreRef().DoneTask(ctx, tenant, id, by, note)
}

// taskID 含时间戳（闭环后重开是新单；幂等由 pending 同源判定，不靠 ID 碰撞）。
func taskID(tenant, assetID, trigger string, ts time.Time) string {
	sum := sha256.Sum256([]byte(tenant + "|" + assetID + "|" + trigger + "|" + ts.Format(time.RFC3339Nano)))
	return "RT-" + hex.EncodeToString(sum[:])[:12]
}
