package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	"github.com/lib/pq"

	"github.com/wangdev88/easm-platform/platform/services/internal/finding"
)

func (d *DB) Findings() *FindingStore { return &FindingStore{d} }

type FindingStore struct{ db *DB }

const findingCols = "id,entity_id,asset_id,type,title,lifecycle,severity,confidence,first_seen,last_seen,source,coalesce(rule_id,''),evidence_refs,note,created_at,updated_at"

func scanFinding(sc interface{ Scan(...any) error }) (finding.Finding, error) {
	var f finding.Finding
	err := sc.Scan(&f.ID, &f.EntityID, &f.AssetID, &f.Type, &f.Title, &f.Lifecycle, &f.Severity,
		&f.Confidence, &f.FirstSeen, &f.LastSeen, &f.Source, &f.RuleID, pq.Array(&f.EvidenceRefs),
		&f.Note, &f.CreatedAt, &f.UpdatedAt)
	return f, err
}

func (s *FindingStore) Create(ctx context.Context, f finding.Finding) error {
	return s.db.withTenant(ctx, f.EntityID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO findings "+
			"(id,entity_id,asset_id,type,title,lifecycle,severity,confidence,first_seen,last_seen,source,rule_id,evidence_refs,note,created_at,updated_at) "+
			"VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
			f.ID, f.EntityID, f.AssetID, f.Type, f.Title, f.Lifecycle, f.Severity, f.Confidence,
			f.FirstSeen, f.LastSeen, f.Source, f.RuleID, pq.Array(textArr(f.EvidenceRefs)), f.Note,
			f.CreatedAt, f.UpdatedAt)
		if isDup(err) {
			return finding.ErrDuplicate
		}
		return err
	})
}

func (s *FindingStore) Get(ctx context.Context, entityID, id string) (finding.Finding, error) {
	var out finding.Finding
	err := s.db.withTenant(ctx, entityID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, "SELECT "+findingCols+" FROM findings WHERE entity_id=$1 AND id=$2", entityID, id)
		var err error
		out, err = scanFinding(row)
		if errors.Is(err, sql.ErrNoRows) {
			return finding.ErrNotFound
		}
		return err
	})
	return out, err
}

func (s *FindingStore) List(ctx context.Context, entityID, lifecycle string, limit int) ([]finding.Finding, error) {
	var out []finding.Finding
	err := s.db.withTenant(ctx, entityID, func(tx *sql.Tx) error {
		q := "SELECT " + findingCols + " FROM findings WHERE entity_id=$1"
		args := []any{entityID}
		if lifecycle != "" {
			q += " AND lifecycle=$2"
			args = append(args, lifecycle)
		}
		q += " ORDER BY last_seen DESC LIMIT $" + strconv.Itoa(len(args)+1)
		args = append(args, limit)
		rows, err := tx.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			f, err := scanFinding(rows)
			if err != nil {
				return err
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

func (s *FindingStore) Update(ctx context.Context, f finding.Finding) error {
	return s.db.withTenant(ctx, f.EntityID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "UPDATE findings SET lifecycle=$3,severity=$4,confidence=$5,last_seen=$6,evidence_refs=$7,note=$8,updated_at=$9 "+
			"WHERE entity_id=$1 AND id=$2",
			f.EntityID, f.ID, f.Lifecycle, f.Severity, f.Confidence, f.LastSeen,
			pq.Array(textArr(f.EvidenceRefs)), f.Note, f.UpdatedAt)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return finding.ErrNotFound
		}
		return nil
	})
}

func (s *FindingStore) AddValidation(ctx context.Context, entityID, findingID string, v finding.Validation) error {
	return s.db.withTenant(ctx, entityID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO finding_validations (finding_id,method,result,evidence_ref,note,by_user,at) "+
			"VALUES ($1,$2,$3,$4,$5,$6,$7)",
			findingID, v.Method, v.Result, v.EvidenceRef, v.Note, v.By, v.At)
		return err
	})
}

func (s *FindingStore) Validations(ctx context.Context, entityID, findingID string) ([]finding.Validation, error) {
	var out []finding.Validation
	err := s.db.withTenant(ctx, entityID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, "SELECT method,result,coalesce(evidence_ref,''),note,by_user,at "+
			"FROM finding_validations WHERE finding_id=$1 ORDER BY at", findingID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v finding.Validation
			if err := rows.Scan(&v.Method, &v.Result, &v.EvidenceRef, &v.Note, &v.By, &v.At); err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, err
}
