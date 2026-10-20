package job

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
)

func TestEnqueueLeaseComplete(t *testing.T) {
	s := New(NewMemStore(), &audit.MemLog{})
	ctx := context.Background()
	j, err := s.Enqueue(ctx, Job{EntityID: "t-a", Kind: "discovery", Payload: map[string]any{"connector": "seed"}})
	if err != nil {
		t.Fatal(err)
	}
	same, err := s.Enqueue(ctx, Job{EntityID: "t-a", Kind: "discovery", Payload: map[string]any{"connector": "seed"}})
	if err != nil {
		t.Fatal(err)
	}
	if same.ID != j.ID {
		t.Fatalf("幂等键应返回同一 job: %s vs %s", j.ID, same.ID)
	}
	leased, err := s.Lease(ctx, "worker-1", 1, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(leased) != 1 || leased[0].State != StateLeased || leased[0].Attempts != 1 {
		t.Fatalf("租约不符: %+v", leased)
	}
	done, err := s.Complete(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.State != StateSucceeded {
		t.Fatalf("完成状态不符: %s", done.State)
	}
	if _, err := s.Complete(ctx, j.ID); !errors.Is(err, ErrState) {
		t.Fatalf("终态重复完成应拒绝，实际 %v", err)
	}
}

func TestFailRetriesThenDead(t *testing.T) {
	s := New(NewMemStore(), &audit.MemLog{}).WithBackoff(0)
	ctx := context.Background()
	j, _ := s.Enqueue(ctx, Job{EntityID: "t-a", Kind: "discovery", MaxAttempts: 2})
	if _, err := s.Lease(ctx, "w", 1, time.Minute); err != nil {
		t.Fatal(err)
	}
	if out, err := s.Fail(ctx, j.ID, "boom"); err != nil || out.State != StateQueued {
		t.Fatalf("首次失败应回队: %+v err=%v", out, err)
	}
	if _, err := s.Lease(ctx, "w", 1, time.Minute); err != nil {
		t.Fatal(err)
	}
	if out, err := s.Fail(ctx, j.ID, "boom2"); err != nil || out.State != StateDead {
		t.Fatalf("超过 max 应 dead: %+v err=%v", out, err)
	}
}

func TestReapExpiredLease(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	s := New(store, &audit.MemLog{})
	j, _ := s.Enqueue(ctx, Job{EntityID: "t-a", Kind: "discovery", MaxAttempts: 3})
	if _, err := store.Lease(ctx, "dead-worker", 1, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	n, err := s.ReapExpired(ctx)
	if err != nil || n != 1 {
		t.Fatalf("reap: n=%d err=%v", n, err)
	}
	got, _ := s.Get(ctx, j.ID)
	if got.State != StateQueued || got.LeaseUntil != nil {
		t.Fatalf("过期租约应回队: %+v", got)
	}
}

func TestReapExpiredDead(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	s := New(store, &audit.MemLog{})
	j, _ := s.Enqueue(ctx, Job{EntityID: "t-a", Kind: "discovery", MaxAttempts: 1})
	if _, err := store.Lease(ctx, "dead-worker", 1, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReapExpired(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(ctx, j.ID)
	if got.State != StateDead {
		t.Fatalf("attempts 用尽应 dead: %s", got.State)
	}
}

func TestCancel(t *testing.T) {
	s := New(NewMemStore(), &audit.MemLog{})
	j, _ := s.Enqueue(context.Background(), Job{EntityID: "t-a", Kind: "discovery"})
	out, err := s.Cancel(context.Background(), j.ID)
	if err != nil || out.State != StateCanceled {
		t.Fatalf("取消失败: %+v err=%v", out, err)
	}
}
