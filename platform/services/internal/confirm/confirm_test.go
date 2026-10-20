package confirm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
)

func admin() rbac.Principal {
	return rbac.Principal{UserID: "u-admin", Role: "admin", TenantIDs: []string{"*"}}
}

func mk(t *testing.T, s *Service, entity, action string) Confirmation {
	t.Helper()
	c, err := s.Create(context.Background(), admin(), "req", Confirmation{
		EntityID: entity, Action: action, Resource: "target:443",
		Method: MethodPasskey, Reason: "监管检查通知 2026-001",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCreateAndConsumeOnce(t *testing.T) {
	s := New(NewMemStore(), &audit.MemLog{})
	c := mk(t, s, "t-a", "scan.port")
	if c.ID == "" || c.OperatorID != "u-admin" {
		t.Fatalf("确认未正确落库: %+v", c)
	}
	if err := s.Consume(context.Background(), admin(), "req", c.ID, "t-a", "scan.port"); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume(context.Background(), admin(), "req", c.ID, "t-a", "scan.port"); !errors.Is(err, ErrConsumed) {
		t.Fatalf("重复消费应拒绝，实际 %v", err)
	}
}

func TestConsumeRejectsWrongEntityOrAction(t *testing.T) {
	s := New(NewMemStore(), &audit.MemLog{})
	c := mk(t, s, "t-a", "scan.port")
	if err := s.Consume(context.Background(), admin(), "req", c.ID, "t-b", "scan.port"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("entity 不匹配应拒绝，实际 %v", err)
	}
	if err := s.Consume(context.Background(), admin(), "req", c.ID, "t-a", "notice.create"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("action 不匹配应拒绝，实际 %v", err)
	}
}

func TestExpiredConfirmationRejected(t *testing.T) {
	s := New(NewMemStore(), &audit.MemLog{}).WithTTL(time.Millisecond)
	c := mk(t, s, "t-a", "scan.port")
	time.Sleep(5 * time.Millisecond)
	if err := s.Consume(context.Background(), admin(), "req", c.ID, "t-a", "scan.port"); !errors.Is(err, ErrExpired) {
		t.Fatalf("过期确认应拒绝，实际 %v", err)
	}
}

func TestCreateDeniedOutsideScope(t *testing.T) {
	s := New(NewMemStore(), &audit.MemLog{})
	p := rbac.Principal{UserID: "u-a", Role: "admin", TenantIDs: []string{"t-a"}}
	_, err := s.Create(context.Background(), p, "req", Confirmation{
		EntityID: "t-b", Action: "scan.port", Resource: "x", Method: MethodPasskey, Reason: "x",
	})
	if !errors.Is(err, rbac.ErrCrossTenant) {
		t.Fatalf("跨 entity 创建确认应拒绝，实际 %v", err)
	}
}

func TestCrossEntityReadDenied(t *testing.T) {
	s := New(NewMemStore(), &audit.MemLog{})
	c := mk(t, s, "t-b", "scan.port")
	p := rbac.Principal{UserID: "u-a", Role: "admin", TenantIDs: []string{"t-a"}}
	if _, err := s.Get(context.Background(), p, "req", c.ID); !errors.Is(err, rbac.ErrCrossTenant) {
		t.Fatalf("跨 entity 读取应拒绝，实际 %v", err)
	}
}
