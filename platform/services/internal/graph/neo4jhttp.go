package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Neo4jHTTP 通过 Neo4j 事务 HTTP API（/db/{db}/tx/commit）读写 Exposure Graph。
// 仅用标准库，避免 M0 引入外部依赖；生产替换官方 driver 不影响本包接口。
type Neo4jHTTP struct {
	Endpoint string // 如 http://localhost:7474
	Database string // 默认 neo4j
	Username string
	Password string
	Client   *http.Client
}

func (n *Neo4jHTTP) db() string {
	if n.Database != "" {
		return n.Database
	}
	return "neo4j"
}

func (n *Neo4jHTTP) client() *http.Client {
	if n.Client != nil {
		return n.Client
	}
	return http.DefaultClient
}

type cypherStatement struct {
	Statement  string         `json:"statement"`
	Parameters map[string]any `json:"parameters"`
}

type commitRequest struct {
	Statements []cypherStatement `json:"statements"`
}

type commitResponse struct {
	Results []struct {
		Columns []string `json:"columns"`
		Data    []struct {
			Row []json.RawMessage `json:"row"`
		} `json:"data"`
	} `json:"results"`
	Errors []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

func (n *Neo4jHTTP) commit(ctx context.Context, stmt cypherStatement) (*commitResponse, error) {
	body, _ := json.Marshal(commitRequest{Statements: []cypherStatement{stmt}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		n.Endpoint+"/db/"+n.db()+"/tx/commit", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(n.Username, n.Password)
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("neo4j http %d: %s", resp.StatusCode, string(raw))
	}
	var out commitResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if len(out.Errors) > 0 {
		return nil, fmt.Errorf("neo4j error %s: %s", out.Errors[0].Code, out.Errors[0].Message)
	}
	return &out, nil
}

// SaveEntity 用 MERGE 实现幂等 upsert（FR-GPH-003）；created 参数仅为接口一致性，
// MERGE 本身保证「同指纹走 merge」。props 以 JSON 串存储，保持属性袋语义。
func (n *Neo4jHTTP) SaveEntity(ctx context.Context, e Entity, _ bool) error {
	propsJSON, _ := json.Marshal(e.Props)
	stmt := cypherStatement{
		Statement: `MERGE (x:Entity {tenant:$tenant, fingerprint:$fingerprint})
ON CREATE SET x.kind=$kind, x.props=$props, x.first_seen=$first_seen, x.last_seen=$last_seen, x.in_scope=$in_scope, x.sources=$sources
ON MATCH  SET x.props=$props, x.last_seen=$last_seen, x.in_scope=$in_scope, x.sources=$sources
RETURN x`,
		Parameters: map[string]any{
			"tenant":      e.Tenant,
			"fingerprint": e.Fingerprint,
			"kind":        e.Kind,
			"props":       string(propsJSON),
			"first_seen":  e.FirstSeen.UTC().Format(time.RFC3339),
			"last_seen":   e.LastSeen.UTC().Format(time.RFC3339),
			"in_scope":    e.InScope,
			"sources":     e.Sources,
		},
	}
	_, err := n.commit(ctx, stmt)
	return err
}

// FindByFingerprint 按 (tenant, fingerprint) 读取实体。
func (n *Neo4jHTTP) FindByFingerprint(ctx context.Context, tenant, fp string) (Entity, bool, error) {
	stmt := cypherStatement{
		Statement: `MATCH (x:Entity {tenant:$tenant, fingerprint:$fingerprint})
RETURN x.kind AS kind, x.props AS props, x.first_seen AS first_seen, x.last_seen AS last_seen, x.in_scope AS in_scope, x.sources AS sources LIMIT 1`,
		Parameters: map[string]any{"tenant": tenant, "fingerprint": fp},
	}
	out, err := n.commit(ctx, stmt)
	if err != nil {
		return Entity{}, false, err
	}
	if len(out.Results) == 0 || len(out.Results[0].Data) == 0 {
		return Entity{}, false, nil
	}
	row := out.Results[0].Data[0].Row
	if len(row) < 6 {
		return Entity{}, false, fmt.Errorf("neo4j: unexpected row %d cols", len(row))
	}
	var kind, propsS, fs, ls string
	var inScope bool
	var sources []string
	if err := json.Unmarshal(row[0], &kind); err != nil {
		return Entity{}, false, err
	}
	if err := json.Unmarshal(row[1], &propsS); err != nil {
		return Entity{}, false, err
	}
	if err := json.Unmarshal(row[2], &fs); err != nil {
		return Entity{}, false, err
	}
	if err := json.Unmarshal(row[3], &ls); err != nil {
		return Entity{}, false, err
	}
	if err := json.Unmarshal(row[4], &inScope); err != nil {
		return Entity{}, false, err
	}
	if err := json.Unmarshal(row[5], &sources); err != nil {
		return Entity{}, false, err
	}
	props := map[string]string{}
	_ = json.Unmarshal([]byte(propsS), &props)
	first, _ := time.Parse(time.RFC3339, fs)
	last, _ := time.Parse(time.RFC3339, ls)
	return Entity{
		Kind: kind, Tenant: tenant, Fingerprint: fp, Props: props,
		FirstSeen: first, LastSeen: last, InScope: inScope, Sources: sources,
	}, true, nil
}

// UpsertRelation 要求两端实体已存在；否则返回 ErrEndpoints（保证引用完整性）。
func (n *Neo4jHTTP) UpsertRelation(ctx context.Context, rel Relation) error {
	propsJSON, _ := json.Marshal(rel.Props)
	stmt := cypherStatement{
		Statement: `MATCH (a:Entity {tenant:$tenant, fingerprint:$from})
MATCH (b:Entity {tenant:$tenant, fingerprint:$to})
MERGE (a)-[r:RELATION {rel_type:$rel_type}]->(b)
ON CREATE SET r.props=$props, r.evidence=$evidence, r.ts=$ts
RETURN count(r) AS n`,
		Parameters: map[string]any{
			"tenant":   rel.Tenant,
			"from":     rel.FromFP,
			"to":       rel.ToFP,
			"rel_type": rel.Type,
			"props":    string(propsJSON),
			"evidence": rel.EvidenceRef,
			"ts":       rel.TS.UTC().Format(time.RFC3339),
		},
	}
	out, err := n.commit(ctx, stmt)
	if err != nil {
		return err
	}
	if len(out.Results) == 0 || len(out.Results[0].Data) == 0 {
		return ErrEndpoints
	}
	var count float64
	if err := json.Unmarshal(out.Results[0].Data[0].Row[0], &count); err != nil {
		return err
	}
	if count == 0 {
		return ErrEndpoints
	}
	return nil
}

var _ Store = (*Neo4jHTTP)(nil)
