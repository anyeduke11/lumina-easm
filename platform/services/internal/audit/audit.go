// Package audit 提供仅追加审计日志（NFR-SEC-006 / CR-001~005）。
// M0 以内存实现打通调用点；生产落 PG（migrations/001_init.sql audit_logs，禁 UPDATE/DELETE）。
package audit

import (
	"context"
	"sync"
	"time"
)

const (
	ResultAllow = "allow"
	ResultDeny  = "deny"
)

type Entry struct {
	TS        time.Time
	Actor     string
	Action    string // 如 asset.read / tenant.create
	TenantID  string
	Resource  string
	Result    string
	RequestID string
}

type Log interface {
	Append(ctx context.Context, e Entry) error
}

type MemLog struct {
	mu      sync.Mutex
	entries []Entry
}

func (l *MemLog) Append(_ context.Context, e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	l.entries = append(l.entries, e)
	return nil
}

// Snapshot 返回副本，防止调用方篡改内部记录。
func (l *MemLog) Snapshot() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, len(l.entries))
	copy(out, l.entries)
	return out
}
