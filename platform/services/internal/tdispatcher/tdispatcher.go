// Package tdispatcher 实现 ENH-01 Temporal 编排 Provider（接缝=派发接口，
// httpapi 侧仅依赖 1-method 接口，SDK 类型不外泄——AX-6 防腐层同构）。
// dev server 经 `temporal server start-dev` 本机启动（非容器，本地化约束下实测可行）。
package tdispatcher

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/wangdev88/easm-platform/platform/services/internal/sweep"
)

const (
	TaskQueue = "easm-sweep"
	// WorkflowType 单一事实源：派发端 ExecuteWorkflow 与 worker 注册端同引此常量（防名称漂移）。
	WorkflowType = "SweepWorkflow"
)

// Dispatcher 满足 httpapi.SweepDispatcher：把已建行交给 Temporal 工作流执行。
type Dispatcher struct {
	c client.Client
}

func New(hostPort string) (*Dispatcher, error) {
	c, err := client.Dial(client.Options{HostPort: hostPort})
	if err != nil {
		return nil, fmt.Errorf("tdispatcher: 连接 Temporal(%s) 失败: %w", hostPort, err)
	}
	return &Dispatcher{c: c}, nil
}

// Input 工作流入参（worker 据此按行续跑）。
type Input struct {
	SweepID string
	Tenant  string
}

func (d *Dispatcher) Dispatch(_ context.Context, sw *sweep.Sweep) error {
	// 显式传类型名（非函数引用）：与 worker 注册名严格同源，杜绝推断漂移。
	_, err := d.c.ExecuteWorkflow(context.Background(), client.StartWorkflowOptions{
		ID:        "sweep-" + sw.ID,
		TaskQueue: TaskQueue,
	}, WorkflowType, Input{SweepID: sw.ID, Tenant: sw.Tenant})
	return err
}

func (d *Dispatcher) Close() { d.c.Close() }

// SweepWorkflow 单 activity 顺序跑完全部阶段：
// 断点续跑由行内 donePhases 跳过 + ledger 去重双保险；
// activity 重试策略（1min×5）承接 worker 崩溃恢复——工作流历史保证「至少一次」，
// 幂等语义（AX-4/A-04）保证「恰好一次」效果。DAG 并行化（P2‖P4）留待 M2 增强。
func SweepWorkflow(wf workflow.Context, in Input) error {
	// StartToClose 可经 env 调短（崩溃演练用；默认 30min 适配真实工具链时长）。
	// 活动幂等（行内 donePhases 跳过 + ledger 去重），超时重试=断点续跑而非重放全部。
	to := 30 * time.Minute
	if v := os.Getenv("EASM_ACTIVITY_STARTTOCLOSE"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 5*time.Second {
			to = d
		}
	}
	ctx := workflow.WithActivityOptions(wf, workflow.ActivityOptions{
		StartToCloseTimeout: to,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval: 5 * time.Second, MaximumInterval: 2 * time.Minute,
			BackoffCoefficient: 2.0, MaximumAttempts: 5,
		},
	})
	// 活动无返回值：Get 的第二参不可为 nil（v1.42 实测双 nil panic），用占位指针接收。
	var discard string
	return workflow.ExecuteActivity(ctx, "SweepExecuteActivity", in).Get(wf, &discard)
}
