package discovery

import (
	"context"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/job"
)

// Worker 消费 discovery job；与 HTTP 进程解耦，可独立部署/多实例。
type Worker struct {
	svc      *Service
	jobs     *job.Service
	owner    string
	interval time.Duration
	lease    time.Duration
}

func NewWorker(svc *Service, jobs *job.Service, owner string) *Worker {
	if owner == "" {
		owner = "discovery-worker"
	}
	return &Worker{svc: svc, jobs: jobs, owner: owner, interval: 2 * time.Second, lease: 5 * time.Minute}
}

func (w *Worker) WithInterval(d time.Duration) *Worker {
	if d > 0 {
		w.interval = d
	}
	return w
}

// RunOnce 领一批任务并执行；返回成功完成数。
func (w *Worker) RunOnce(ctx context.Context, limit int) (int, error) {
	if _, err := w.jobs.ReapExpired(ctx); err != nil {
		return 0, err
	}
	leased, err := w.jobs.Lease(ctx, w.owner, limit, w.lease)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, j := range leased {
		if _, err := w.svc.RunJob(ctx, j); err != nil {
			_, _ = w.jobs.Fail(ctx, j.ID, err.Error())
			continue
		}
		if _, err := w.jobs.Complete(ctx, j.ID); err != nil {
			return done, err
		}
		done++
	}
	return done, nil
}

// Run 持续消费，直到 ctx 取消。
func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		_, _ = w.RunOnce(ctx, 10)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
