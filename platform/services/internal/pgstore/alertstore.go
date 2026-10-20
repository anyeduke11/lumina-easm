// Package pgstore 提供 PostgreSQL 存储实现（WP-M0-03/04）。
package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	"github.com/wangdev88/easm-platform/platform/services/internal/alert"
)

func (d *DB) Alerts() *AlertStore { return &AlertStore{d} }

type AlertStore struct{ db *DB }

const alertCols = "id,entity_id,finding_id,severity,title,status,source,created_at,acked_at,acked_by"

func scanAlert(sc interface{ Scan(...any) error }) (alert.Alert, error) {
	var a alert.Alert
	var acked sql.NullTime
	err := sc.Scan(&a.ID, &a.EntityID, &a.FindingID, &a.Severity, &a.Title, &a.Status,
		&a.Source, &a.CreatedAt, &acked, &a.AckedBy)
	if acked.Valid {
		t := acked.Time
		a.AckedAt = &t
	}
	return a, err
}

func (s *AlertStore) Create(ctx context.Context, a alert.Alert) (alert.Alert, error) {
	var out alert.Alert
	err := s.db.withTenant(ctx, a.EntityID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, "INSERT INTO alerts "+
			"(id,entity_id,finding_id,severity,title,status,source,created_at,acked_at,acked_by) "+
			"VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) "+
			"ON CONFLICT (entity_id,finding_id) DO NOTHING RETURNING "+alertCols,
			a.ID, a.EntityID, a.FindingID, a.Severity, a.Title, a.Status, a.Source, a.CreatedAt, a.AckedAt, a.AckedBy)
		var err error
		out, err = scanAlert(row)
		if errors.Is(err, sql.ErrNoRows) {
			row = tx.QueryRowContext(ctx, "SELECT "+alertCols+" FROM alerts WHERE entity_id=$1 AND finding_id=$2", a.EntityID, a.FindingID)
			out, err = scanAlert(row)
		}
		return err
	})
	return out, err
}

func (s *AlertStore) Get(ctx context.Context, entityID, id string) (alert.Alert, error) {
	var out alert.Alert
	err := s.db.withTenant(ctx, entityID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, "SELECT "+alertCols+" FROM alerts WHERE entity_id=$1 AND id=$2", entityID, id)
		var err error
		out, err = scanAlert(row)
		if errors.Is(err, sql.ErrNoRows) {
			return alert.ErrNotFound
		}
		return err
	})
	return out, err
}

func (s *AlertStore) List(ctx context.Context, entityID, status string, limit int) ([]alert.Alert, error) {
	var out []alert.Alert
	err := s.db.withTenant(ctx, entityID, func(tx *sql.Tx) error {
		q := "SELECT " + alertCols + " FROM alerts WHERE entity_id=$1"
		args := []any{entityID}
		if status != "" {
			q += " AND status=$2"
			args = append(args, status)
		}
		q += " ORDER BY created_at DESC LIMIT $" + strconv.Itoa(len(args)+1)
		args = append(args, limit)
		rows, err := tx.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanAlert(rows)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func (s *AlertStore) Update(ctx context.Context, a alert.Alert) error {
	return s.db.withTenant(ctx, a.EntityID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "UPDATE alerts SET status=$3,acked_at=$4,acked_by=$5 WHERE entity_id=$1 AND id=$2",
			a.EntityID, a.ID, a.Status, a.AckedAt, a.AckedBy)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return alert.ErrNotFound
		}
		return nil
	})
}
