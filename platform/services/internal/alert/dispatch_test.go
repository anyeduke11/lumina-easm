package alert

import (
	"context"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
)

type fakeNotifier struct {
	got      []monitor.Alert
	channels []string
}

func (f *fakeNotifier) Dispatch(_ context.Context, _ string, alerts []monitor.Alert) (int, int, error) {
	f.got = append(f.got, alerts...)
	return len(alerts), 0, nil
}
func (f *fakeNotifier) Channels() []string { return f.channels }

func TestAutoDispatchOnRaise(t *testing.T) {
	s := New(NewMemStore(), &audit.MemLog{})
	f := &fakeNotifier{channels: []string{"webhook"}}
	s.WithNotifier(f).WithAutoDispatch(true)
	if _, err := s.Raise(context.Background(), Alert{EntityID: "t-a", FindingID: "FND-auto", Severity: "high", Title: "secret"}); err != nil {
		t.Fatal(err)
	}
	if len(f.got) != 1 {
		t.Fatalf("auto dispatch got=%d", len(f.got))
	}
}

func TestDispatchOpenAlerts(t *testing.T) {
	s := New(NewMemStore(), &audit.MemLog{})
	f := &fakeNotifier{channels: []string{"webhook"}}
	s.WithNotifier(f)
	ctx := context.Background()
	if _, err := s.Raise(ctx, Alert{EntityID: "t-a", FindingID: "FND-1", Severity: "high", Title: "secret"}); err != nil {
		t.Fatal(err)
	}
	sent, skipped, err := s.Dispatch(ctx, "t-a", "webhook")
	if err != nil || sent != 1 || skipped != 0 || len(f.got) != 1 {
		t.Fatalf("dispatch: sent=%d skipped=%d err=%v got=%d", sent, skipped, err, len(f.got))
	}
	if len(s.Channels()) != 1 {
		t.Fatal("channels 未透传")
	}
}
