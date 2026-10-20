package pgstore

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/alert"
	"github.com/wangdev88/easm-platform/platform/services/internal/finding"
	"github.com/wangdev88/easm-platform/platform/services/internal/inventory"
	"github.com/wangdev88/easm-platform/platform/services/internal/job"
)

func TestPhase1StoresIntegration(t *testing.T) {
	dsn := os.Getenv("EASM_PG_DSN")
	if dsn == "" {
		t.Skip("EASM_PG_DSN 未设置，跳过 PG 集成")
	}
	db, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	entity := "itest-phase1-" + time.Now().UTC().Format("20060102150405")
	t.Cleanup(func() {
		_ = db.withTenant(ctx, entity, func(tx *sql.Tx) error {
			_, _ = tx.Exec("DELETE FROM finding_validations WHERE finding_id IN (SELECT id FROM findings WHERE entity_id=$1)", entity)
			_, _ = tx.Exec("DELETE FROM alerts WHERE entity_id=$1", entity)
			_, _ = tx.Exec("DELETE FROM findings WHERE entity_id=$1", entity)
			_, _ = tx.Exec("DELETE FROM inventory_observations WHERE entity_id=$1", entity)
			_, _ = tx.Exec("DELETE FROM inventory_aliases WHERE entity_id=$1", entity)
			_, _ = tx.Exec("DELETE FROM inventory_assets WHERE entity_id=$1", entity)
			_, _ = tx.Exec("DELETE FROM jobs WHERE entity_id=$1", entity)
			return nil
		})
	})

	inv := db.Inventory()
	now := time.Now().UTC().Truncate(time.Millisecond)
	a := inventory.Asset{
		ID: "INV-itest", EntityID: entity, Kind: "domain", CanonicalKey: "dom:itest.example",
		DisplayName: "itest.example", State: inventory.StateCandidate, Confidence: 0.5,
		FirstSeen: now, LastSeen: now, Sources: []string{"seed"}, Attributes: map[string]string{"value": "itest.example"},
	}
	got, err := inv.UpsertAsset(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != a.ID || got.EntityID != entity {
		t.Fatalf("upsert 不符: %+v", got)
	}
	if err := inv.AddAlias(ctx, inventory.Alias{EntityID: entity, AssetID: a.ID, AliasKey: "itest.example", AliasType: "value", FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	if byAlias, ok, err := inv.FindByAlias(ctx, entity, "itest.example"); err != nil || !ok || byAlias.ID != a.ID {
		t.Fatalf("alias 查找失败: %+v ok=%v err=%v", byAlias, ok, err)
	}
	obs := inventory.Observation{
		ID: "OBS-itest", EntityID: entity, AssetID: a.ID, AssetKey: a.CanonicalKey,
		Kind: "domain", SourceID: "seed", ObservedAt: now, PayloadHash: "h-itest", Payload: map[string]string{"seed": "x"},
	}
	if st, err := inv.UpdateState(ctx, entity, a.ID, inventory.StateConfirmed, "verified", now); err != nil || st.State != inventory.StateConfirmed {
		t.Fatalf("update state: %+v err=%v", st, err)
	}
	if created, err := inv.AppendObservation(ctx, obs); err != nil || !created {
		t.Fatalf("append obs: created=%v err=%v", created, err)
	}
	if created, err := inv.AppendObservation(ctx, obs); err != nil || created {
		t.Fatalf("重复 obs 应幂等: created=%v err=%v", created, err)
	}
	list, err := inv.List(ctx, entity, 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %d %v", len(list), err)
	}

	fs := db.Findings()
	f := finding.Finding{
		ID: "FND-itest", EntityID: entity, AssetID: a.ID, Type: "exposed_secret", Title: "t",
		Lifecycle: finding.LifecycleNew, Severity: "high", Confidence: 0.8,
		FirstSeen: now, LastSeen: now, Source: "seed", CreatedAt: now, UpdatedAt: now,
	}
	if err := fs.Create(ctx, f); err != nil {
		t.Fatal(err)
	}
	if err := fs.AddValidation(ctx, entity, f.ID, finding.Validation{Method: "manual", Result: finding.ResultConfirmed, EvidenceRef: "evidence://itest", By: "u1", At: now}); err != nil {
		t.Fatal(err)
	}
	vals, err := fs.Validations(ctx, entity, f.ID)
	if err != nil || len(vals) != 1 {
		t.Fatalf("validations: %d %v", len(vals), err)
	}
	f.Lifecycle = finding.LifecycleConfirmed
	f.EvidenceRefs = []string{"evidence://itest"}
	if err := fs.Update(ctx, f); err != nil {
		t.Fatal(err)
	}
	if got, err := fs.Get(ctx, entity, f.ID); err != nil || got.Lifecycle != finding.LifecycleConfirmed {
		t.Fatalf("finding get: %+v err=%v", got, err)
	}

	js := db.Jobs()
	j, err := js.Enqueue(ctx, job.Job{
		ID: "JOB-itest", EntityID: entity, Kind: "discovery", Payload: map[string]any{"connector": "seed"},
		State: job.StateQueued, IdempotencyKey: "itest-phase1-job", MaxAttempts: 2,
		CreatedAt: now, NextRunAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	leased, err := js.Lease(ctx, "itest-worker", 10, now.Add(time.Minute))
	if err != nil || len(leased) == 0 {
		t.Fatalf("lease: %d %v", len(leased), err)
	}
	j.State = job.StateSucceeded
	if err := js.Update(ctx, j); err != nil {
		t.Fatal(err)
	}
	if got, err := js.Get(ctx, j.ID); err != nil || got.State != job.StateSucceeded {
		t.Fatalf("job get: %+v err=%v", got, err)
	}
	if list, err := js.List(ctx, entity, "", 10); err != nil || len(list) != 1 {
		t.Fatalf("job list all: %d %v", len(list), err)
	}
	if list, err := js.List(ctx, entity, job.StateSucceeded, 10); err != nil || len(list) != 1 {
		t.Fatalf("job list state: %d %v", len(list), err)
	}

	reapJob, err := js.Enqueue(ctx, job.Job{
		ID: "JOB-itest-reap", EntityID: entity, Kind: "discovery", Payload: map[string]any{"connector": "seed"},
		State: job.StateQueued, IdempotencyKey: "itest-phase1-reap", MaxAttempts: 3,
		CreatedAt: now, NextRunAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Lease(ctx, "dead-worker", 10, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if n, err := js.ReapExpired(ctx, now); err != nil || n == 0 {
		t.Fatalf("reap expired: n=%d err=%v", n, err)
	}
	if got, err := js.Get(ctx, reapJob.ID); err != nil || got.State != job.StateQueued {
		t.Fatalf("reaped job: %+v err=%v", got, err)
	}

	as := db.Alerts()
	al, err := as.Create(ctx, alert.Alert{ID: "ALT-itest", EntityID: entity, FindingID: f.ID, Severity: "high", Title: "t", Status: alert.StatusOpen, Source: "test", CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := as.Get(ctx, entity, al.ID); err != nil || got.FindingID != f.ID {
		t.Fatalf("alert get: %+v err=%v", got, err)
	}
	if list, err := as.List(ctx, entity, "", 10); err != nil || len(list) != 1 {
		t.Fatalf("alert list: %d %v", len(list), err)
	}
	al.Status = alert.StatusAck
	al.AckedBy = "u1"
	if err := as.Update(ctx, al); err != nil {
		t.Fatal(err)
	}
}
