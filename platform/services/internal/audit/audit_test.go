package audit

import (
	"context"
	"testing"
	"time"
)

// 为什么：审计是仅追加的证据链（NFR-SEC-006 / CR-001）——
// Snapshot 若暴露内部切片引用，调用方可篡改历史，取证效力即失效。
func TestMemLogAppendOnlyAndSnapshotIsolation(t *testing.T) {
	l := &MemLog{}
	_ = l.Append(context.Background(), Entry{Actor: "u1", Action: "asset.read", Result: ResultDeny})
	snap := l.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("期望 1 条审计，实际 %d", len(snap))
	}
	if snap[0].TS.IsZero() {
		t.Error("Append 应自动填充时间戳")
	}
	// 篡改快照不得影响内部记录
	snap[0].Actor = "hacked"
	if got := l.Snapshot()[0].Actor; got == "hacked" {
		t.Error("Snapshot 必须是副本，不可暴露内部存储引用")
	}

	// 显式时间戳应保留
	fixed := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	_ = l.Append(context.Background(), Entry{TS: fixed, Actor: "u2", Action: "x", Result: ResultAllow})
	if got := l.Snapshot()[1].TS; !got.Equal(fixed) {
		t.Errorf("显式时间戳应保留，实际 %v", got)
	}
}
