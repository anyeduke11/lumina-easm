package inventory

import (
	"context"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
)

func TestIngestMergesAndKeepsObservations(t *testing.T) {
	s := New(NewMemStore(), &audit.MemLog{})
	ctx := context.Background()
	a, created, err := s.Ingest(ctx, "t-a", Observation{Kind: "domain", Value: "Example.com.", SourceID: "ct"})
	if err != nil {
		t.Fatal(err)
	}
	if !created || a.CanonicalKey != "dom:example.com" {
		t.Fatalf("首次摄取不符: %+v created=%v", a, created)
	}
	b, created2, err := s.Ingest(ctx, "t-a", Observation{Kind: "domain", Value: "example.com", SourceID: "dns"})
	if err != nil {
		t.Fatal(err)
	}
	if created2 || b.ID != a.ID {
		t.Fatalf("同域应合并: a=%s b=%s created=%v", a.ID, b.ID, created2)
	}
	obs, err := s.Observations(ctx, "t-a", a.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 2 {
		t.Fatalf("应保留两条来源观察，实际 %d", len(obs))
	}
	aliases, err := s.Aliases(ctx, "t-a", a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(aliases) == 0 {
		t.Fatal("应写入别名")
	}
}

func TestIngestIdempotentObservation(t *testing.T) {
	s := New(NewMemStore(), &audit.MemLog{})
	ctx := context.Background()
	in := Observation{Kind: "url", Value: "https://a.example/", SourceID: "seed", ObservedAt: time.Now().UTC()}
	a, _, err := s.Ingest(ctx, "t-a", in)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Ingest(ctx, "t-a", in); err != nil {
		t.Fatal(err)
	}
	obs, _ := s.Observations(ctx, "t-a", a.ID, 10)
	if len(obs) != 1 {
		t.Fatalf("同源同值应幂等，实际 %d", len(obs))
	}
}

func TestAssetStateMachine(t *testing.T) {
	ctx := context.Background()
	s := New(NewMemStore(), &audit.MemLog{})
	a, _, err := s.Ingest(ctx, "t-a", Observation{Kind: "domain", Value: "sm.example", SourceID: "seed"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetState(ctx, "t-a", a.ID, StateActive, "", "u"); err == nil {
		t.Fatal("candidate -> active 应拒绝")
	}
	if _, err := s.SetState(ctx, "t-a", a.ID, StateConfirmed, "verified", "u"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetState(ctx, "t-a", a.ID, StateActive, "in use", "u"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetState(ctx, "t-a", a.ID, StateRetired, "", "u"); err == nil {
		t.Fatal("retired 无原因应拒绝")
	}
	out, err := s.SetState(ctx, "t-a", a.ID, StateRetired, "decommissioned", "u")
	if err != nil || out.State != StateRetired {
		t.Fatalf("retire 失败: %+v err=%v", out, err)
	}
	if _, err := s.SetState(ctx, "t-a", a.ID, StateActive, "back", "u"); err == nil {
		t.Fatal("retired 是终态")
	}
}

func TestDecayAssets(t *testing.T) {
	ctx := context.Background()
	s := New(NewMemStore(), &audit.MemLog{})
	old, _, err := s.Ingest(ctx, "t-a", Observation{Kind: "domain", Value: "old.example", SourceID: "seed", ObservedAt: time.Now().Add(-100 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetState(ctx, "t-a", old.ID, StateConfirmed, "verified", "u"); err != nil {
		t.Fatal(err)
	}
	stale, _, err := s.Ingest(ctx, "t-a", Observation{Kind: "domain", Value: "stale.example", SourceID: "seed", ObservedAt: time.Now().Add(-40 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetState(ctx, "t-a", stale.ID, StateConfirmed, "verified", "u"); err != nil {
		t.Fatal(err)
	}
	n, err := s.Decay(ctx, "t-a", 30*24*time.Hour, 90*24*time.Hour, "decay")
	if err != nil || n != 2 {
		t.Fatalf("decay n=%d err=%v", n, err)
	}
	gotOld, _ := s.Get(ctx, "t-a", old.ID)
	gotStale, _ := s.Get(ctx, "t-a", stale.ID)
	if gotOld.State != StateRetired || gotStale.State != StateStale {
		t.Fatalf("decay state: old=%s stale=%s", gotOld.State, gotStale.State)
	}
}

func TestNormalizeRejectsUnknownKind(t *testing.T) {
	if _, _, _, err := Normalize("mystery", "x"); err == nil {
		t.Fatal("未知 kind 应拒绝")
	}
}
