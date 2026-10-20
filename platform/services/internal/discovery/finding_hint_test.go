package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/connector"
	"github.com/wangdev88/easm-platform/platform/services/internal/finding"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/inventory"
	"github.com/wangdev88/easm-platform/platform/services/internal/job"
)

type findingConnector struct{}

func (findingConnector) Name() string { return "fake-finding" }
func (findingConnector) Run(context.Context, connector.Input) ([]connector.Observation, error) {
	return []connector.Observation{{
		Kind: "url", Value: "https://leak.example/x", SourceID: "fake",
		Finding: &connector.FindingHint{
			Type: "exposed_secret", Title: "secret in page", Severity: "high",
			RuleID: "rule-1", EvidenceRef: "evidence://x",
		},
	}}, nil
}

func TestDiscoveryEmitsFindingHint(t *testing.T) {
	ctx := context.Background()
	inv := inventory.New(inventory.NewMemStore(), &audit.MemLog{})
	fnd := finding.New(finding.NewMemStore(), &audit.MemLog{})
	jobs := job.New(job.NewMemStore(), &audit.MemLog{})
	reg := connector.NewRegistry()
	if err := reg.Register(findingConnector{}); err != nil {
		t.Fatal(err)
	}
	svc := New(inv, graph.NewService(graph.NewMemStore()), jobs, reg).WithFindings(fnd)
	j, err := svc.Enqueue(ctx, "t-a", "fake-finding", nil)
	if err != nil {
		t.Fatal(err)
	}
	leased, err := jobs.Lease(ctx, "w", 1, time.Minute)
	if err != nil || len(leased) != 1 {
		t.Fatalf("lease: %v %d", err, len(leased))
	}
	res, err := svc.RunJob(ctx, leased[0])
	if err != nil {
		t.Fatal(err)
	}
	if res.Findings != 1 {
		t.Fatalf("findings 计数不符: %+v", res)
	}
	out, err := fnd.List(ctx, "t-a", "", 10)
	if err != nil || len(out) != 1 || out[0].Type != "exposed_secret" {
		t.Fatalf("finding 未落库: %+v err=%v", out, err)
	}
	_ = j
}
