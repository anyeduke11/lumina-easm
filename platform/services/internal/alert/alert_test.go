package alert

import (
	"context"
	"errors"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
)

func TestRaiseAck(t *testing.T) {
	s := New(NewMemStore(), &audit.MemLog{})
	ctx := context.Background()
	a, err := s.Raise(ctx, Alert{EntityID: "t-a", FindingID: "FND-1", Severity: "high", Title: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	same, err := s.Raise(ctx, Alert{EntityID: "t-a", FindingID: "FND-1", Severity: "high", Title: "secret"})
	if err != nil || same.ID != a.ID {
		t.Fatalf("幂等失败: %s vs %s err=%v", same.ID, a.ID, err)
	}
	acked, err := s.Ack(ctx, "t-a", a.ID, "u1")
	if err != nil || acked.Status != StatusAck || acked.AckedBy != "u1" {
		t.Fatalf("ack 失败: %+v err=%v", acked, err)
	}
	if _, err := s.Ack(ctx, "t-a", a.ID, "u1"); !errors.Is(err, ErrState) {
		t.Fatalf("重复 ack 应拒绝，实际 %v", err)
	}
	list, _ := s.List(ctx, "t-a", StatusAck, 10)
	if len(list) != 1 {
		t.Fatalf("list 不符: %d", len(list))
	}
}
