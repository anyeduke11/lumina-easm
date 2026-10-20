package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/connector"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/inventory"
	"github.com/wangdev88/easm-platform/platform/services/internal/job"
)

func TestDiscoveryEndToEnd(t *testing.T) {
	ctx := context.Background()
	inv := inventory.New(inventory.NewMemStore(), &audit.MemLog{})
	gmem := graph.NewMemStore()
	gsvc := graph.NewService(gmem)
	jobs := job.New(job.NewMemStore(), &audit.MemLog{})
	reg := connector.NewRegistry()
	if err := reg.Register(connector.Seed{}); err != nil {
		t.Fatal(err)
	}
	svc := New(inv, gsvc, jobs, reg)

	j, err := svc.Enqueue(ctx, "t-a", "seed", []string{"Example.com", "192.0.2.10", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	leased, err := jobs.Lease(ctx, "w1", 1, time.Minute)
	if err != nil || len(leased) != 1 {
		t.Fatalf("lease: %v %d", err, len(leased))
	}
	res, err := svc.RunJob(ctx, leased[0])
	if err != nil {
		t.Fatal(err)
	}
	if res.Observations != 2 || res.Assets != 2 || res.Created != 2 {
		t.Fatalf("结果不符: %+v", res)
	}
	assets, err := inv.List(ctx, "t-a", 10)
	if err != nil || len(assets) != 2 {
		t.Fatalf("资产数不符: %v %d", err, len(assets))
	}
	ents, err := gmem.Entities(ctx, "t-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 3 { // org + domain + ip
		t.Fatalf("图谱实体数不符: %d %+v", len(ents), ents)
	}
	rels, err := gmem.Relations(ctx, "t-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 2 { // org owns domain + org owns ip
		t.Fatalf("图谱边数不符: %d %+v", len(rels), rels)
	}

	done, err := jobs.Complete(ctx, j.ID)
	if err != nil || done.State != job.StateSucceeded {
		t.Fatalf("完成 job 失败: %+v %v", done, err)
	}
}

func TestDiscoveryWorkerRunOnce(t *testing.T) {
	ctx := context.Background()
	inv := inventory.New(inventory.NewMemStore(), &audit.MemLog{})
	jobs := job.New(job.NewMemStore(), &audit.MemLog{})
	reg := connector.NewRegistry()
	_ = reg.Register(connector.Seed{})
	svc := New(inv, nil, jobs, reg)
	w := NewWorker(svc, jobs, "w-test")
	j, err := svc.Enqueue(ctx, "t-a", "seed", []string{"a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	n, err := w.RunOnce(ctx, 10)
	if err != nil || n != 1 {
		t.Fatalf("RunOnce: n=%d err=%v", n, err)
	}
	got, err := jobs.Get(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != job.StateSucceeded {
		t.Fatalf("job 状态不符: %s", got.State)
	}
}

func TestEnqueueRejectsUnknownConnector(t *testing.T) {
	reg := connector.NewRegistry()
	svc := New(nil, nil, job.New(job.NewMemStore(), nil), reg)
	if _, err := svc.Enqueue(context.Background(), "t-a", "nope", nil); err == nil {
		t.Fatal("未注册 connector 应拒绝")
	}
}
