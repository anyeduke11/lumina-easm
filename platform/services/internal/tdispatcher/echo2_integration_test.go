package tdispatcher

import (
	"context"
	"os"
	"testing"
	"time"

	"go.temporal.io/sdk/activity"
	sdkclient "go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

// 分层定位：string 入参 vs Input 结构体入参——哪个在活动执行器侧挂起。
func TestTemporalEchoInput(t *testing.T) {
	host := os.Getenv("EASM_TEMPORAL_HOST")
	if host == "" {
		t.Skip("EASM_TEMPORAL_HOST 未设置")
	}
	c, err := sdkclient.Dial(sdkclient.Options{HostPort: host})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	q := "easm-test-input"
	w := worker.New(c, q, worker.Options{})
	w.RegisterWorkflowWithOptions(EchoInputWorkflow, workflow.RegisterOptions{Name: "EchoInputWorkflow"})
	w.RegisterActivityWithOptions(InputEchoActivity, activity.RegisterOptions{Name: "InputEchoActivity"})
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	run, err := c.ExecuteWorkflow(context.Background(), sdkclient.StartWorkflowOptions{
		ID: "echoinput-" + t.Name(), TaskQueue: q,
	}, "EchoInputWorkflow", Input{SweepID: "S-X", Tenant: "t-x"})
	if err != nil {
		t.Fatal(err)
	}
	var got string
	done := make(chan struct{})
	go func() { defer close(done); err = run.Get(context.Background(), &got) }()
	select {
	case <-done:
		if err != nil {
			t.Fatalf("get err: %v", err)
		}
		t.Logf("OK got=%q", got)
	case <-time.After(25 * time.Second):
		t.Fatal("挂起：Input 结构体入参活动未执行（25s）")
	}
}

func InputEchoActivity(_ context.Context, in Input) (string, error) {
	return "got:" + in.SweepID + "/" + in.Tenant, nil
}

func EchoInputWorkflow(wf workflow.Context, in Input) (string, error) {
	ctx := workflow.WithActivityOptions(wf, workflow.ActivityOptions{StartToCloseTimeout: time.Minute})
	var out string
	if err := workflow.ExecuteActivity(ctx, "InputEchoActivity", in).Get(wf, &out); err != nil {
		return "", err
	}
	return out, nil
}
