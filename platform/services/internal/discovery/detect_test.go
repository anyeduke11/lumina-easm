package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/connector"
	"github.com/wangdev88/easm-platform/platform/services/internal/detect"
	"github.com/wangdev88/easm-platform/platform/services/internal/finding"
	"github.com/wangdev88/easm-platform/platform/services/internal/inventory"
	"github.com/wangdev88/easm-platform/platform/services/internal/job"
)

type detectConnector struct{}

func (detectConnector) Name() string { return "fake-detect" }
func (detectConnector) Run(context.Context, connector.Input) ([]connector.Observation, error) {
	return []connector.Observation{{
		Kind: "url", Value: "https://leak.example/config", SourceID: "fake",
		Payload: map[string]string{"body": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"},
	}}, nil
}

func TestDiscoveryAutoDetectFinding(t *testing.T) {
	ctx := context.Background()
	inv := inventory.New(inventory.NewMemStore(), &audit.MemLog{})
	fnd := finding.New(finding.NewMemStore(), &audit.MemLog{})
	jobs := job.New(job.NewMemStore(), &audit.MemLog{})
	reg := connector.NewRegistry()
	_ = reg.Register(detectConnector{})
	svc := New(inv, nil, jobs, reg).WithFindings(fnd).WithDetector(detect.New(fnd))
	if _, err := svc.Enqueue(ctx, "t-a", "fake-detect", nil); err != nil {
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
	if res.Findings == 0 {
		t.Fatal("应自动创建 Finding")
	}
	list, _ := fnd.List(ctx, "t-a", "", 10)
	if len(list) == 0 {
		t.Fatal("Finding 未落库")
	}
}
