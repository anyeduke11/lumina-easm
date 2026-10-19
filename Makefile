GO ?= go
PSQL ?= /opt/homebrew/opt/postgresql@18/bin/psql
PG_ADMIN_DSN ?= -h 127.0.0.1 -U <admin-user> -d easm
EASM_APP_DSN ?= postgres://easm_app:easm-***@127.0.0.1:5432/easm?sslmode=disable

.PHONY: build test test-integ vet lint trace run run-local migrate dev-up dev-down

verify: ## M0/M1 收尾验证套件（前置：server@18080 PG 模式 + MinIO + 迁移全应用）
	$(MAKE) test-integ
	bash scripts/kb-smoke.sh
	python3 scripts/live-smoke.py
	bash scripts/authz-sop-drill.sh
	@echo "VERIFY OK — 集成回归 + 端到端三件套 + 授权 SOP 预演 全绿"

build:
	$(GO) build ./...

test:
	$(GO) test ./... -count=1

vet:
	$(GO) vet ./...

lint:
	golangci-lint run

trace: ## V-7 追溯对账（C-1：每个 Go 包注释须携带 FR/WP/IR/CR/ENH 编号）
	python3 scripts/trace-check.py

# dev 令牌演示：token:role:租户列表（* 为全部），格式见 cmd/server/main.go parseTokens
run:
	EASM_DEV_TOKENS="tok-admin:R7:*,tok-ops:R1:t-a" $(GO) run ./platform/services/cmd/server

# MVP 本地化部署（无容器）：仅依赖 brew services start postgresql@18 + make migrate
run-local:
	EASM_PG_DSN="$(EASM_APP_DSN)" EASM_DEV_TOKENS="tok-admin:R7:*,tok-ops:R1:t-a" $(GO) run ./platform/services/cmd/server

migrate:
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/001_init.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/002_role_app.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/003_graph.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/004_ledger.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/005_knowledge.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/006_sweeps.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/007_authz.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/008_diff.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/009_notify_log.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/010_darkweb.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/011_workorder.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/012_notice.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/013_report.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/014_review_queue.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/015_ledger_xchk.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/016_candidate_accepted.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/017_ledger_refute.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/018_ledger_verifs.sql
	$(PSQL) $(PG_ADMIN_DSN) -v ON_ERROR_STOP=1 -f migrations/019_evalset.sql

temporal-dev: ## ENH-01：本机非容器 Temporal dev server（brew install temporal）
	temporal server start-dev --ip 127.0.0.1

run-worker: ## ENH-01：Temporal 编排 worker（与 server 共享 EASM_PG_DSN）
	EASM_PG_DSN="$(EASM_APP_DSN)" $(GO) run ./platform/services/cmd/worker

test-integ:
	EASM_PG_DSN="$(EASM_APP_DSN)" $(GO) test ./... -count=1

backup: ## 全库快照（001–007 对象含 sweeps/auth_scopes 事实源；custom 格式可 pg_restore）
	@mkdir -p backups
	/opt/homebrew/opt/postgresql@18/bin/pg_dump -h 127.0.0.1 -U duke -d easm -Fc -f backups/easm-$$(date +%Y%m%d-%H%M%S).dump
	@ls -t backups | head -1 | xargs -I{} echo "backup ok: backups/{}（保留最近 7 份可手动清理）"

# 以下 compose 路径暂缓启用（开发环境无容器）；生产 K8s 方案不变（设计方案 §9）
dev-up:
	docker compose -f deploy/docker-compose.dev.yml up -d

dev-down:
	docker compose -f deploy/docker-compose.dev.yml down
