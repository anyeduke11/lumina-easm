// cmd/worker：Temporal 编排 worker（ENH-01 装载件）。
// 与 server 共享 PG 事实源（sweeps/ledger/assets/authz）；接缝不变——
// 活动内调 sweep.Service.ExecuteInto，与进程内回退路径同一执行核。
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	sdklog "go.temporal.io/sdk/log"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"

	"github.com/wangdev88/easm-platform/platform/services/internal/authz"
	"github.com/wangdev88/easm-platform/platform/services/internal/classify"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/pgstore"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/sweep"
	"github.com/wangdev88/easm-platform/platform/services/internal/tdispatcher"
)

// systemPrincipal worker 执行主体（等同 R7 全量；对外授权闸仍逐租户 auth_scope 强制）。
var systemPrincipal = rbac.Principal{UserID: "temporal-worker", Role: "R7", TenantIDs: []string{"*"}}

type Activities struct{ svc *sweep.Service }

// globalActs 顶层函数注册的桥（见 main 中注释：结构体+自定义 Name 在 v1.42 的活动永不派发）。
var globalActs *Activities

// SweepExecuteActivity 按行续跑（授权闸/去重/断点跳过都在 ExecuteInto→run 内，与同步路径零分叉 C-6）。
// 返回汇总字符串而非 void：void 活动结果在部分 SDK/转换器组合下触发空 payload 解码异常
// （端到端实测：worker 领任务后静默挂起），有值返回同时便于 UI/历史可观测。
func SweepExecuteActivity(ctx context.Context, in tdispatcher.Input) (string, error) {
	return globalActs.runActivity(ctx, in)
}

// 方法版（保留单测可用性；worker 进程注册的是上面顶层函数包装）。
func (a *Activities) runActivity(ctx context.Context, in tdispatcher.Input) (string, error) {
	log.Printf("[activity] start sweep id=%s tenant=%s attempt=%d", in.SweepID, in.Tenant, activity.GetInfo(ctx).Attempt)
	if os.Getenv("EASM_WORKER_ECHO") == "1" { // 诊断档：跳过业务体，验证派发环
		return "echo:" + in.SweepID, nil
	}
	// 崩溃演练档：EASM_ACTIVITY_CRASHAT=N —— 首个 attempt 在第 N 步落盘后强制失败，
	// 重试轮清除注入；确定性验证「行保留断点 + ExecuteInto 续跑」全链。
	if fa := os.Getenv("EASM_ACTIVITY_CRASHAT"); fa != "" {
		if n, err2 := strconv.Atoi(fa); err2 == nil && activity.GetInfo(ctx).Attempt == 1 {
			a.svc.StepHook = func(sw *sweep.Sweep) error {
				if len(sw.Steps) >= n {
					a.svc.StepHook = nil
					return fmt.Errorf("simulated crash at step %d (sweep %s)", n, sw.ID)
				}
				return nil
			}
		}
	}
	sw, err := a.svc.ExecuteInto(ctx, systemPrincipal, "temporal", in.SweepID)
	if err != nil {
		if sw != nil {
			return "", fmt.Errorf("sweep %s: %w", in.SweepID, err)
		}
		return "", err
	}
	return fmt.Sprintf("done:%s:findings=%d:steps=%d", sw.Status, sw.Findings, len(sw.Steps)), nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// slogLevel EASM_WORKER_LOG=debug 开 SDK debug 轨迹（端到端排障用）。
func slogLevel() *slog.HandlerOptions {
	if os.Getenv("EASM_WORKER_LOG") == "debug" {
		return &slog.HandlerOptions{Level: slog.LevelDebug}
	}
	return &slog.HandlerOptions{Level: slog.LevelInfo}
}

func main() {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		log.Fatal("EASM_PG_DSN 必填：worker 与 server 共享 PG 事实源（跨进程断点语义的前提）")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		log.Fatalf("连接 PG 失败: %v", err)
	}
	lg := ledger.NewService(db.Ledgers(), db.Audit())
	svc := sweep.NewService(db.Assets(), classify.New(), lg)
	svc.SetStore(db.Sweeps())                              // 006：sweep 行跨进程事实源
	svc.SetScope(authz.NewService(db.Authz(), db.Audit())) // 同一授权闸（一票否决⑥，worker 不旁路）

	c, err := client.Dial(client.Options{
		HostPort: env("EASM_TEMPORAL_HOST", "127.0.0.1:7233"),
		Logger:   sdklog.NewStructuredLogger(slog.New(slog.NewTextHandler(os.Stderr, slogLevel()))),
	})
	if err != nil {
		log.Fatalf("连接 Temporal 失败: %v", err)
	}
	defer c.Close()
	w := worker.New(c, tdispatcher.TaskQueue, worker.Options{})
	w.RegisterWorkflowWithOptions(tdispatcher.SweepWorkflow, workflow.RegisterOptions{Name: tdispatcher.WorkflowType})
	// 顶层函数注册（端到端实测：v1.42 下结构体+自定义 Name 的活动被 poller 认领后永不 Started，
	// 顶层函数注册同队列同参数正常执行——差异定位用 echo2 用例复现）
	globalActs = &Activities{svc: svc}
	w.RegisterActivityWithOptions(SweepExecuteActivity, activity.RegisterOptions{Name: "SweepExecuteActivity"})

	log.Printf("easm temporal worker listening queue=%s host=%s", tdispatcher.TaskQueue, env("EASM_TEMPORAL_HOST", "127.0.0.1:7233"))
	if err := w.Start(); err != nil {
		log.Fatal(err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("worker 收到退出信号，限时优雅停止（10s 未完成则强退；活动幂等+Temporal 重派兜底）")
	stopped := make(chan struct{})
	go func() { w.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		os.Exit(1) // 防「挂死活动阻塞 GracefulStop → 孤儿 poller 抢任务」事故链
	}
}
