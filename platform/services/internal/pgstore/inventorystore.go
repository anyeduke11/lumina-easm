package pgstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/lib/pq"

	"github.com/wangdev88/easm-platform/platform/services/internal/inventory"
)

func (d *DB) Inventory() *InventoryStore { return &InventoryStore{d} }

type InventoryStore struct{ db *DB }

const inventoryCols = "id,entity_id,kind,canonical_key,display_name,state,confidence,first_seen,last_seen,sources,attributes,state_reason,state_changed_at"

const inventoryColsA = "a.id,a.entity_id,a.kind,a.canonical_key,a.display_name,a.state,a.confidence,a.first_seen,a.last_seen,a.sources,a.attributes,a.state_reason,a.state_changed_at"

func scanInventory(sc interface{ Scan(...any) error }) (inventory.Asset, error) {
	var a inventory.Asset
	var attrs []byte
	var changed sql.NullTime
	err := sc.Scan(&a.ID, &a.EntityID, &a.Kind, &a.CanonicalKey, &a.DisplayName, &a.State,
		&a.Confidence, &a.FirstSeen, &a.LastSeen, pq.Array(&a.Sources), &attrs, &a.StateReason, &changed)
	if err != nil {
		return inventory.Asset{}, err
	}
	if len(attrs) > 0 {
		_ = json.Unmarshal(attrs, &a.Attributes)
	}
	if a.Attributes == nil {
		a.Attributes = map[string]string{}
	}
	if changed.Valid {
		a.StateChangedAt = changed.Time
	}
	return a, nil
}

func (s *InventoryStore) UpsertAsset(ctx context.Context, a inventory.Asset) (inventory.Asset, error) {
	attrs, _ := json.Marshal(a.Attributes)
	var out inventory.Asset
	err := s.db.withTenant(ctx, a.EntityID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `INSERT INTO inventory_assets
(id,entity_id,kind,canonical_key,display_name,state,confidence,first_seen,last_seen,sources,attributes)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::text[],$11::jsonb)
ON CONFLICT (entity_id,kind,canonical_key) DO UPDATE SET
  last_seen = GREATEST(inventory_assets.last_seen, EXCLUDED.last_seen),
  first_seen = LEAST(inventory_assets.first_seen, EXCLUDED.first_seen),
  confidence = GREATEST(inventory_assets.confidence, EXCLUDED.confidence),
  state = CASE WHEN inventory_assets.state='retired' THEN EXCLUDED.state ELSE inventory_assets.state END,
  sources = ARRAY(SELECT DISTINCT unnest(inventory_assets.sources || EXCLUDED.sources)),
  attributes = inventory_assets.attributes || EXCLUDED.attributes
RETURNING `+inventoryCols,
			a.ID, a.EntityID, a.Kind, a.CanonicalKey, a.DisplayName, a.State, a.Confidence,
			a.FirstSeen, a.LastSeen, pq.Array(textArr(a.Sources)), string(attrs))
		var err error
		out, err = scanInventory(row)
		return err
	})
	return out, err
}

func (s *InventoryStore) Get(ctx context.Context, entityID, id string) (inventory.Asset, error) {
	var out inventory.Asset
	err := s.db.withTenant(ctx, entityID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, "SELECT "+inventoryCols+" FROM inventory_assets WHERE entity_id=$1 AND id=$2", entityID, id)
		var err error
		out, err = scanInventory(row)
		if errors.Is(err, sql.ErrNoRows) {
			return inventory.ErrNotFound
		}
		return err
	})
	return out, err
}

func (s *InventoryStore) List(ctx context.Context, entityID string, limit int) ([]inventory.Asset, error) {
	var out []inventory.Asset
	err := s.db.withTenant(ctx, entityID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, "SELECT "+inventoryCols+" FROM inventory_assets WHERE entity_id=$1 ORDER BY last_seen DESC LIMIT $2", entityID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanInventory(rows)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func (s *InventoryStore) UpdateState(ctx context.Context, entityID, assetID, to, reason string, at time.Time) (inventory.Asset, error) {
	var out inventory.Asset
	err := s.db.withTenant(ctx, entityID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, "UPDATE inventory_assets SET state=$3,state_reason=$4,state_changed_at=$5 "+
			"WHERE entity_id=$1 AND id=$2 RETURNING "+inventoryCols,
			entityID, assetID, to, reason, at)
		var err error
		out, err = scanInventory(row)
		if errors.Is(err, sql.ErrNoRows) {
			return inventory.ErrNotFound
		}
		return err
	})
	return out, err
}

func (s *InventoryStore) AddAlias(ctx context.Context, a inventory.Alias) error {
	return s.db.withTenant(ctx, a.EntityID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO inventory_aliases
(entity_id,asset_id,alias_key,alias_type,source_id,first_seen,last_seen)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (entity_id,asset_id,alias_key) DO UPDATE SET
  last_seen = GREATEST(inventory_aliases.last_seen, EXCLUDED.last_seen),
  first_seen = LEAST(inventory_aliases.first_seen, EXCLUDED.first_seen)`,
			a.EntityID, a.AssetID, a.AliasKey, a.AliasType, a.SourceID, a.FirstSeen, a.LastSeen)
		return err
	})
}

func (s *InventoryStore) Aliases(ctx context.Context, entityID, assetID string) ([]inventory.Alias, error) {
	var out []inventory.Alias
	err := s.db.withTenant(ctx, entityID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT entity_id,asset_id,alias_key,alias_type,coalesce(source_id,''),first_seen,last_seen
FROM inventory_aliases WHERE entity_id=$1 AND asset_id=$2 ORDER BY alias_key`, entityID, assetID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a inventory.Alias
			if err := rows.Scan(&a.EntityID, &a.AssetID, &a.AliasKey, &a.AliasType, &a.SourceID, &a.FirstSeen, &a.LastSeen); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func (s *InventoryStore) FindByAlias(ctx context.Context, entityID, alias string) (inventory.Asset, bool, error) {
	var out inventory.Asset
	found := false
	err := s.db.withTenant(ctx, entityID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT `+inventoryColsA+` FROM inventory_assets a
JOIN inventory_aliases al ON al.asset_id = a.id AND al.entity_id = a.entity_id
WHERE a.entity_id=$1 AND al.alias_key=$2 LIMIT 1`, entityID, alias)
		var err error
		out, err = scanInventory(row)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	return out, found, err
}

func (s *InventoryStore) AppendObservation(ctx context.Context, o inventory.Observation) (bool, error) {
	payload, _ := json.Marshal(o.Payload)
	created := false
	err := s.db.withTenant(ctx, o.EntityID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO inventory_observations
(id,entity_id,asset_id,asset_key,source_id,observed_at,raw_ref,payload_hash,payload)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)
ON CONFLICT (entity_id,payload_hash) DO NOTHING`,
			o.ID, o.EntityID, o.AssetID, o.AssetKey, o.SourceID, o.ObservedAt, o.RawRef, o.PayloadHash, string(payload))
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		created = n > 0
		return nil
	})
	return created, err
}

func (s *InventoryStore) Observations(ctx context.Context, entityID, assetID string, limit int) ([]inventory.Observation, error) {
	var out []inventory.Observation
	err := s.db.withTenant(ctx, entityID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id,entity_id,asset_id,asset_key,source_id,observed_at,
coalesce(raw_ref,''),payload_hash,payload FROM inventory_observations
WHERE entity_id=$1 AND asset_id=$2 ORDER BY observed_at DESC LIMIT $3`, entityID, assetID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var o inventory.Observation
			var payload []byte
			if err := rows.Scan(&o.ID, &o.EntityID, &o.AssetID, &o.AssetKey, &o.SourceID, &o.ObservedAt,
				&o.RawRef, &o.PayloadHash, &payload); err != nil {
				return err
			}
			_ = json.Unmarshal(payload, &o.Payload)
			if o.Payload == nil {
				o.Payload = map[string]string{}
			}
			o.ObservedAt = o.ObservedAt.UTC()
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}
