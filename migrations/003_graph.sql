-- WP-M0-06（MVP 本地化）· Exposure Graph 落 PG：
-- Neo4j 不在开发环境可用，MVP 以关系表承载 实体+关系（同一本体，接口不变），
-- 生产切回 Neo4j 由 graph.Store 接缝 Provider 替换（设计方案 §4.2 能力接缝）。
BEGIN;

CREATE TABLE IF NOT EXISTS graph_nodes (
  fingerprint text NOT NULL,
  tenant_id   text NOT NULL REFERENCES tenants(id),
  kind        text NOT NULL,
  props       jsonb NOT NULL DEFAULT '{}',
  first_seen  timestamptz NOT NULL,
  last_seen   timestamptz NOT NULL,
  in_scope    boolean NOT NULL DEFAULT false,
  sources     text[] NOT NULL DEFAULT '{}',
  PRIMARY KEY (tenant_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS graph_edges (
  id          bigserial PRIMARY KEY,
  tenant_id   text NOT NULL REFERENCES tenants(id),
  rel_type    text NOT NULL,
  from_fp     text NOT NULL,
  to_fp       text NOT NULL,
  props       jsonb NOT NULL DEFAULT '{}',
  evidence    text,
  ts          timestamptz NOT NULL,
  UNIQUE (tenant_id, rel_type, from_fp, to_fp)
);
CREATE INDEX IF NOT EXISTS idx_edges_from ON graph_edges(tenant_id, from_fp);
CREATE INDEX IF NOT EXISTS idx_nodes_tenant ON graph_nodes(tenant_id);

-- MVP 视图：一跳邻接（FR-GPH-004 的最小子集；多跳/最短路径在生产 Neo4j 落地）
CREATE OR REPLACE VIEW graph_adjacency AS
SELECT tenant_id, from_fp AS fp, rel_type, to_fp AS neighbor, 'out' AS direction, evidence, ts
  FROM graph_edges
UNION ALL
SELECT tenant_id, to_fp AS fp, rel_type, from_fp AS neighbor, 'in' AS direction, evidence, ts
  FROM graph_edges;

GRANT SELECT, INSERT, UPDATE, DELETE ON graph_nodes, graph_edges TO easm_app;
GRANT USAGE, SELECT ON SEQUENCE graph_edges_id_seq TO easm_app;

COMMIT;
