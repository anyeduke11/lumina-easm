package finding

import (
	"context"
	"errors"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
)

func mkFinding(t *testing.T, s *Service) Finding {
	t.Helper()
	f, err := s.Create(context.Background(), Finding{
		EntityID: "t-a", AssetID: "INV-1", Type: "exposed_secret",
		Title: "repo secret", Severity: "high", Source: "gitleaks",
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFindingLifecycle(t *testing.T) {
	s := New(NewMemStore(), &audit.MemLog{})
	f := mkFinding(t, s)
	if f.Lifecycle != LifecycleNew {
		t.Fatalf("初始状态不符: %s", f.Lifecycle)
	}
	if _, err := s.Validate(context.Background(), "t-a", f.ID, "u1", Validation{Method: "manual", Result: ResultConfirmed}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("confirmed 无证据应拒绝，实际 %v", err)
	}
	got, err := s.Validate(context.Background(), "t-a", f.ID, "u1", Validation{
		Method: "manual", Result: ResultConfirmed, EvidenceRef: "evidence://x",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Lifecycle != LifecycleConfirmed {
		t.Fatalf("验证后应为 confirmed，实际 %s", got.Lifecycle)
	}
	closed, err := s.Close(context.Background(), "t-a", f.ID, "u1", "fixed")
	if err != nil {
		t.Fatal(err)
	}
	if closed.Lifecycle != LifecycleClosed {
		t.Fatalf("关闭状态不符: %s", closed.Lifecycle)
	}
	if _, err := s.Close(context.Background(), "t-a", f.ID, "u1", "again"); !errors.Is(err, ErrState) {
		t.Fatalf("终态重复关闭应拒绝，实际 %v", err)
	}
}

func TestFindingRefutedCannotClose(t *testing.T) {
	s := New(NewMemStore(), &audit.MemLog{})
	f := mkFinding(t, s)
	got, err := s.Validate(context.Background(), "t-a", f.ID, "u1", Validation{Method: "manual", Result: ResultRefuted})
	if err != nil {
		t.Fatal(err)
	}
	if got.Lifecycle != LifecycleFalse {
		t.Fatalf("refuted 应为 false_positive，实际 %s", got.Lifecycle)
	}
	if _, err := s.Close(context.Background(), "t-a", f.ID, "u1", "x"); !errors.Is(err, ErrState) {
		t.Fatalf("false_positive 不应可关闭，实际 %v", err)
	}
}

func TestFindingCrossEntityHidden(t *testing.T) {
	s := New(NewMemStore(), &audit.MemLog{})
	f := mkFinding(t, s)
	if _, err := s.Get(context.Background(), "t-b", f.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("跨 entity 读取应 404，实际 %v", err)
	}
}
