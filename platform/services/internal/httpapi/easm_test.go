package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/alert"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/connector"
	"github.com/wangdev88/easm-platform/platform/services/internal/detect"
	"github.com/wangdev88/easm-platform/platform/services/internal/discovery"
	"github.com/wangdev88/easm-platform/platform/services/internal/finding"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/inventory"
	"github.com/wangdev88/easm-platform/platform/services/internal/job"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
	"github.com/wangdev88/easm-platform/platform/services/internal/notify"
	"github.com/wangdev88/easm-platform/platform/services/internal/projection"
)

func phase1Server(t *testing.T) (*httptest.Server, *inventory.Service, *finding.Service, *job.Service) {
	t.Helper()
	inv := inventory.New(inventory.NewMemStore(), &audit.MemLog{})
	fnd := finding.New(finding.NewMemStore(), &audit.MemLog{})
	jobs := job.New(job.NewMemStore(), &audit.MemLog{})
	reg := connector.NewRegistry()
	_ = reg.Register(connector.Seed{})
	disc := discovery.New(inv, graph.NewService(graph.NewMemStore()), jobs, reg)
	proj := projection.New(ledger.NewService(ledger.NewMemStore(), &audit.MemLog{}))
	alerts := alert.New(alert.NewMemStore(), &audit.MemLog{})
	noti := notify.New()
	noti.AddChannel("fake", func(context.Context, monitor.Alert) error { return nil })
	alerts.WithNotifier(noti)
	det := detect.New(fnd).WithAlerts(alerts)
	srv, _ := newConfirmTestServer(t, false, WithInventory(inv), WithFindings(fnd), WithJobs(jobs), WithDiscovery(disc), WithProjection(proj), WithAlerts(alerts), WithDetector(det))
	return srv, inv, fnd, jobs
}

func TestPhase1InventoryAndDiscoveryEndpoints(t *testing.T) {
	srv, _, _, _ := phase1Server(t)
	body, _ := json.Marshal(map[string]any{"kind": "domain", "value": "Example.com", "source_id": "manual"})
	resp, out := post(t, srv.URL, "/v1/tenants/t-a/observations", "tok-admin", string(body))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("ingest 期望 201，实际 %d body=%s", resp.StatusCode, out)
	}
	var created map[string]any
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatal(err)
	}
	asset, _ := created["asset"].(map[string]any)
	aid, _ := asset["id"].(string)
	if aid == "" {
		t.Fatalf("asset id 缺失: %v", created)
	}
	stateBody, _ := json.Marshal(map[string]any{"state": "confirmed", "reason": "verified"})
	resp, out = post(t, srv.URL, "/v1/tenants/t-a/inventory/"+aid+"/state", "tok-admin", string(stateBody))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("state 期望 200，实际 %d body=%s", resp.StatusCode, out)
	}
	resp, outMap := get(srv, "/v1/tenants/t-a/inventory", "tok-admin")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inventory 期望 200，实际 %d body=%v", resp.StatusCode, outMap)
	}
	discBody, _ := json.Marshal(map[string]any{"connector": "seed", "seeds": []string{"a.example.com"}})
	resp, out = post(t, srv.URL, "/v1/tenants/t-a/discovery", "tok-admin", string(discBody))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("discovery 期望 201，实际 %d body=%s", resp.StatusCode, out)
	}
	resp, outMap = get(srv, "/v1/tenants/t-a/jobs", "tok-admin")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jobs 期望 200，实际 %d body=%v", resp.StatusCode, outMap)
	}
}

func TestPhase2ObservationAutoFinding(t *testing.T) {
	srv, _, fnd, _ := phase1Server(t)
	body, _ := json.Marshal(map[string]any{
		"kind": "url", "value": "https://leak.example/config", "source_id": "manual",
		"payload": map[string]string{"body": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"},
	})
	resp, out := post(t, srv.URL, "/v1/tenants/t-a/observations", "tok-admin", string(body))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("ingest 期望 201，实际 %d body=%s", resp.StatusCode, out)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if n, _ := res["findings"].(float64); n == 0 {
		t.Fatalf("应自动创建 Finding: %s", out)
	}
	list, err := fnd.List(context.Background(), "t-a", "", 10)
	if err != nil || len(list) == 0 {
		t.Fatalf("Finding 未落库: %d %v", len(list), err)
	}
}

func TestPhase3BulkFindings(t *testing.T) {
	srv, _, fnd, _ := phase1Server(t)
	ctx := context.Background()
	var ids []string
	for _, title := range []string{"bulk-a", "bulk-b"} {
		f, err := fnd.Create(ctx, finding.Finding{
			EntityID: "t-a", AssetID: "INV-x", Type: "sensitive_data",
			Title: title, Severity: "high", Source: "seed",
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, f.ID)
	}
	body, _ := json.Marshal(map[string]any{"action": "confirm", "ids": ids, "evidence_ref": "evidence://bulk"})
	resp, out := post(t, srv.URL, "/v1/tenants/t-a/findings:bulk", "tok-admin", string(body))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bulk confirm 期望 200，实际 %d body=%s", resp.StatusCode, out)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if n, _ := res["ok"].(float64); int(n) != len(ids) {
		t.Fatalf("bulk confirm ok=%v body=%s", res["ok"], out)
	}
	projBody, _ := json.Marshal(map[string]any{"action": "project", "ids": ids})
	resp, out = post(t, srv.URL, "/v1/tenants/t-a/findings:bulk", "tok-admin", string(projBody))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bulk project 期望 200，实际 %d body=%s", resp.StatusCode, out)
	}
}

func TestPhase1RejectsUnknownEntity(t *testing.T) {
	srv, _, _, _ := phase1Server(t)
	body, _ := json.Marshal(map[string]any{"kind": "domain", "value": "x.example", "source_id": "manual"})
	resp, out := post(t, srv.URL, "/v1/tenants/t-missing/observations", "tok-admin", string(body))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("未知 entity 期望 404，实际 %d body=%s", resp.StatusCode, out)
	}
}

func TestPhase1FindingLifecycleEndpoints(t *testing.T) {
	srv, _, _, _ := phase1Server(t)
	body, _ := json.Marshal(map[string]any{
		"asset_id": "INV-x", "type": "exposed_secret", "title": "secret",
		"severity": "high", "source": "seed",
	})
	resp, out := post(t, srv.URL, "/v1/tenants/t-a/findings", "tok-admin", string(body))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create finding 期望 201，实际 %d body=%s", resp.StatusCode, out)
	}
	var f map[string]any
	if err := json.Unmarshal([]byte(out), &f); err != nil {
		t.Fatal(err)
	}
	id, _ := f["id"].(string)
	if id == "" {
		t.Fatalf("finding id 缺失: %v", f)
	}
	bad, _ := json.Marshal(map[string]any{"method": "manual", "result": "confirmed"})
	resp, out = post(t, srv.URL, "/v1/tenants/t-a/findings/"+id+"/validate", "tok-admin", string(bad))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("无证据 confirmed 期望 400，实际 %d body=%s", resp.StatusCode, out)
	}
	ok, _ := json.Marshal(map[string]any{"method": "manual", "result": "confirmed", "evidence_ref": "evidence://x"})
	resp, out = post(t, srv.URL, "/v1/tenants/t-a/findings/"+id+"/validate", "tok-admin", string(ok))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("validate 期望 200，实际 %d body=%s", resp.StatusCode, out)
	}
	var outMap map[string]any
	resp, outMap = get(srv, "/v1/tenants/t-a/alerts", "tok-admin")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("alerts 期望 200，实际 %d body=%v", resp.StatusCode, outMap)
	}
	resp, out = post(t, srv.URL, "/v1/tenants/t-a/alerts:dispatch", "tok-admin", "{\"channel\":\"fake\"}")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dispatch 期望 200，实际 %d body=%s", resp.StatusCode, out)
	}
	resp, out = post(t, srv.URL, "/v1/tenants/t-a/findings/"+id+"/project", "tok-admin", "{}")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("project 期望 200，实际 %d body=%s", resp.StatusCode, out)
	}
	closeBody, _ := json.Marshal(map[string]any{"note": "fixed"})
	resp, out = post(t, srv.URL, "/v1/tenants/t-a/findings/"+id+"/close", "tok-admin", string(closeBody))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("close 期望 200，实际 %d body=%s", resp.StatusCode, out)
	}
}
