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

type dnsLike struct{}

func (dnsLike) Name() string { return "fake-dns" }
func (dnsLike) Run(context.Context, connector.Input) ([]connector.Observation, error) {
	return []connector.Observation{{
		Kind: "ip", Value: "192.0.2.20", SourceID: "dns",
		Payload: map[string]string{"resolves_from": "dns.example"},
	}}, nil
}

func TestDiscoveryWritesResolvesToEdge(t *testing.T) {
	ctx := context.Background()
	inv := inventory.New(inventory.NewMemStore(), &audit.MemLog{})
	gmem := graph.NewMemStore()
	g := graph.NewService(gmem)
	jobs := job.New(job.NewMemStore(), &audit.MemLog{})
	reg := connector.NewRegistry()
	_ = reg.Register(dnsLike{})
	svc := New(inv, g, jobs, reg)
	if _, err := svc.Enqueue(ctx, "t-a", "fake-dns", nil); err != nil {
		t.Fatal(err)
	}
	leased, err := jobs.Lease(ctx, "w", 1, time.Minute)
	if err != nil || len(leased) != 1 {
		t.Fatalf("lease: %v %d", err, len(leased))
	}
	if _, err := svc.RunJob(ctx, leased[0]); err != nil {
		t.Fatal(err)
	}
	rels, err := gmem.Relations(ctx, "t-a")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rels {
		if r.Type == graph.RelResolvesTo {
			found = true
		}
	}
	if !found {
		t.Fatalf("应写入 resolves_to 边: %+v", rels)
	}
	ents, _ := gmem.Entities(ctx, "t-a")
	if len(ents) != 3 { // org + ip + domain
		t.Fatalf("实体数不符: %d %+v", len(ents), ents)
	}
}
