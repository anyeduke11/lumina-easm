package pgstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/job"
)

func (d *DB) Jobs() *JobStore { return &JobStore{d} }

type JobStore struct{ db *DB }

const jobCols = "id,entity_id,kind,payload,state,priority,idempotency_key,attempts,max_attempts,coalesce(lease_owner,''),lease_until,coalesce(last_error,''),created_at,started_at,finished_at,next_run_at"

const jobColsJ = "j.id,j.entity_id,j.kind,j.payload,j.state,j.priority,j.idempotency_key,j.attempts,j.max_attempts,coalesce(j.lease_owner,''),j.lease_until,coalesce(j.last_error,''),j.created_at,j.started_at,j.finished_at,j.next_run_at"

func scanJob(sc interface{ Scan(...any) error }) (job.Job, error) {
	var j job.Job
	var payload []byte
	var leaseUntil, started, finished sql.NullTime
	err := sc.Scan(&j.ID, &j.EntityID, &j.Kind, &payload, &j.State, &j.Priority, &j.IdempotencyKey,
		&j.Attempts, &j.MaxAttempts, &j.LeaseOwner, &leaseUntil, &j.LastError,
		&j.CreatedAt, &started, &finished, &j.NextRunAt)
	if err != nil {
		return job.Job{}, err
	}
	if len(payload) > 0 {
		_ = json.Unmarshal(payload, &j.Payload)
	}
	if j.Payload == nil {
		j.Payload = map[string]any{}
	}
	if leaseUntil.Valid {
		t := leaseUntil.Time
		j.LeaseUntil = &t
	}
	if started.Valid {
		t := started.Time
		j.StartedAt = &t
	}
	if finished.Valid {
		t := finished.Time
		j.FinishedAt = &t
	}
	return j, nil
}

func (s *JobStore) Enqueue(ctx context.Context, j job.Job) (job.Job, error) {
	payload, _ := json.Marshal(j.Payload)
	var out job.Job
	err := s.db.withTenant(ctx, j.EntityID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, "INSERT INTO jobs "+
			"(id,entity_id,kind,payload,state,priority,idempotency_key,attempts,max_attempts,lease_owner,lease_until,last_error,created_at,started_at,finished_at,next_run_at) "+
			"VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,NULL,NULL,'',$10,NULL,NULL,$11) "+
			"ON CONFLICT (idempotency_key) DO NOTHING RETURNING "+jobCols,
			j.ID, j.EntityID, j.Kind, string(payload), j.State, j.Priority, j.IdempotencyKey,
			j.Attempts, j.MaxAttempts, j.CreatedAt, j.NextRunAt)
		var err error
		out, err = scanJob(row)
		if errors.Is(err, sql.ErrNoRows) {
			row = tx.QueryRowContext(ctx, "SELECT "+jobCols+" FROM jobs WHERE idempotency_key=$1", j.IdempotencyKey)
			out, err = scanJob(row)
		}
		return err
	})
	return out, err
}

func (s *JobStore) Get(ctx context.Context, id string) (job.Job, error) {
	var out job.Job
	err := s.db.withTenant(ctx, "", func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, "SELECT "+jobCols+" FROM jobs WHERE id=$1", id)
		var err error
		out, err = scanJob(row)
		if errors.Is(err, sql.ErrNoRows) {
			return job.ErrNotFound
		}
		return err
	})
	return out, err
}

func (s *JobStore) List(ctx context.Context, entityID, state string, limit int) ([]job.Job, error) {
	var out []job.Job
	err := s.db.withTenant(ctx, entityID, func(tx *sql.Tx) error {
		q := "SELECT " + jobCols + " FROM jobs WHERE ($1='' OR entity_id=$1)"
		args := []any{entityID}
		if state != "" {
			q += " AND state=$2"
			args = append(args, state)
		}
		q += " ORDER BY created_at DESC LIMIT $" + strconv.Itoa(len(args)+1)
		args = append(args, limit)
		rows, err := tx.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			j, err := scanJob(rows)
			if err != nil {
				return err
			}
			out = append(out, j)
		}
		return rows.Err()
	})
	return out, err
}

func (s *JobStore) Lease(ctx context.Context, owner string, limit int, leaseUntil time.Time) ([]job.Job, error) {
	var out []job.Job
	err := s.db.withTenant(ctx, "", func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `WITH picked AS (
  SELECT id FROM jobs
  WHERE state='queued' AND next_run_at <= now()
  ORDER BY priority DESC, created_at
  FOR UPDATE SKIP LOCKED
  LIMIT $1
)
UPDATE jobs j SET state='leased', lease_owner=$2, lease_until=$3,
  attempts=j.attempts+1, started_at=COALESCE(j.started_at, now())
FROM picked WHERE j.id=picked.id
RETURNING `+jobColsJ, limit, owner, leaseUntil)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			j, err := scanJob(rows)
			if err != nil {
				return err
			}
			out = append(out, j)
		}
		return rows.Err()
	})
	return out, err
}

func (s *JobStore) ReapExpired(ctx context.Context, now time.Time) (int, error) {
	total := 0
	err := s.db.withTenant(ctx, "", func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "UPDATE jobs SET state='queued', lease_owner='', lease_until=NULL, "+
			"next_run_at=$1, last_error=coalesce(last_error,'') || ' lease expired' "+
			"WHERE state IN ('leased','running') AND lease_until < $1 AND attempts < max_attempts", now)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		total += int(n)
		res, err = tx.ExecContext(ctx, "UPDATE jobs SET state='dead', finished_at=$1, lease_owner='', lease_until=NULL, "+
			"last_error=coalesce(last_error,'') || ' lease expired (max attempts)' "+
			"WHERE state IN ('leased','running') AND lease_until < $1 AND attempts >= max_attempts", now)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		total += int(n)
		return nil
	})
	return total, err
}

func (s *JobStore) Update(ctx context.Context, j job.Job) error {
	payload, _ := json.Marshal(j.Payload)
	return s.db.withTenant(ctx, j.EntityID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "UPDATE jobs SET state=$3,payload=$4::jsonb,priority=$5,attempts=$6,"+
			"lease_owner=$7,lease_until=$8,last_error=$9,started_at=$10,finished_at=$11,next_run_at=$12 "+
			"WHERE id=$1 AND ($2='' OR entity_id=$2)",
			j.ID, j.EntityID, j.State, string(payload), j.Priority, j.Attempts,
			j.LeaseOwner, j.LeaseUntil, j.LastError, j.StartedAt, j.FinishedAt, j.NextRunAt)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return job.ErrNotFound
		}
		return nil
	})
}
