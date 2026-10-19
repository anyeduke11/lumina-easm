// notify.LogStore 的 PostgreSQL 实现（009_notify_log.sql）。
package pgstore

import (
	"context"
	"strings"

	"github.com/wangdev88/easm-platform/platform/services/internal/notify"
)

type NotifyLog struct{ db *DB }

func (d *DB) NotifyLog() *NotifyLog { return &NotifyLog{d} }

var _ notify.LogStore = (*NotifyLog)(nil)

// LogDispatch 追加留痕；ON CONFLICT DO NOTHING=重复 dispatch 不复制历史（幂等）。
func (s *NotifyLog) LogDispatch(channel string, keys []string) error {
	for _, k := range keys {
		if _, err := s.db.sql.ExecContext(context.Background(),
			`INSERT INTO notify_log(channel,dedup_key,alert_key) VALUES($1,$2,$3) ON CONFLICT (dedup_key) DO NOTHING`,
			channel, k, strings.TrimPrefix(k, channel+"|")); err != nil {
			return err
		}
	}
	return nil
}

func (s *NotifyLog) LoadedKeys(channel string) ([]string, error) {
	rs, err := s.db.sql.QueryContext(context.Background(), `SELECT dedup_key FROM notify_log WHERE channel=$1`, channel)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []string
	for rs.Next() {
		var k string
		if err := rs.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rs.Err()
}
