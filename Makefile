GO ?= go
MIGRATE_DSN ?= postgres://$(USER)@127.0.0.1:5432/easm?sslmode=disable
EASM_APP_DSN ?= postgres://easm_app:easm-***@127.0.0.1:5432/easm?sslmode=disable

.PHONY: build test test-integ vet lint trace openapi run run-local run-jobworker migrate migrate-status migrate-baseline start-all stop-all status-all

verify: ## M0/M1 收尾验证套件（前置：server@18080 PG 模式 + MinIO + 迁移全应用）
	$(MAKE) test-integ
	python3 scripts/openapi-check.py
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

openapi: ## 生成并校验 OpenAPI 路由覆盖（/v1/entities 与 /v1/tenants 别名）
	python3 scripts/gen-openapi.py
	python3 scripts/openapi-check.py

# 单用户监管形态：一枚操作员令牌；entity 数据域用 tenant/RLS 承载（* 为全部单位）
run:
	EASM_SINGLE_USER=1 EASM_DEV_TOKENS="tok-admin:R7:*" $(GO) run ./platform/services/cmd/server

# MVP 本地化部署（无容器）：仅依赖 brew services start postgresql@18 + make migrate
run-local:
	EASM_SINGLE_USER=1 EASM_PG_DSN="$(EASM_APP_DSN)" EASM_DEV_TOKENS="tok-admin:R7:*" $(GO) run ./platform/services/cmd/server

# 一键服务管理（编译产物+PID 文件收敛；env 覆盖见 scripts/easm.env.example）
start:
	bash scripts/service.sh start server
stop:
	bash scripts/service.sh stop server
restart:
	bash scripts/service.sh restart server
status:
	-@bash scripts/service.sh status server
	-@bash scripts/service.sh status worker
logs:
	bash scripts/service.sh logs server
start-worker:
	bash scripts/service.sh start worker
stop-worker:
	bash scripts/service.sh stop worker

start-all: ## 一键启动全系统：PG→迁移→server→jobworker→（EASM_TEMPORAL_HOST 已设时）Temporal+worker
	bash scripts/start-all.sh
stop-all: ## 一键停止全系统（PG 为共享依赖，不在停止范围）
	bash scripts/stop-all.sh
status-all:
	-@bash scripts/service.sh status server
	-@bash scripts/service.sh status jobworker
	-@bash scripts/service.sh status worker

migrate: ## 应用 001–024（schema_migrations 记录；需管理员 DSN）
	EASM_MIGRATE_DSN="$(MIGRATE_DSN)" $(GO) run ./platform/services/cmd/migrate up

migrate-status: ## 查看已应用/待应用迁移
	EASM_MIGRATE_DSN="$(MIGRATE_DSN)" $(GO) run ./platform/services/cmd/migrate status

migrate-baseline: ## 既有库首次接入：标记 001–024 已应用（不执行）
	EASM_MIGRATE_DSN="$(MIGRATE_DSN)" $(GO) run ./platform/services/cmd/migrate -yes baseline

temporal-dev: ## ENH-01：本机非容器 Temporal dev server（brew install temporal）
	temporal server start-dev --ip 127.0.0.1

run-worker: ## ENH-01：Temporal 编排 worker（与 server 共享 EASM_PG_DSN）
	EASM_PG_DSN="$(EASM_APP_DSN)" $(GO) run ./platform/services/cmd/worker

run-jobworker: ## Phase 1/2：发现 + 判敏 Job Worker（SQL SKIP LOCKED 租约；需 PG）
	EASM_PG_DSN="$(EASM_APP_DSN)" $(GO) run ./platform/services/cmd/jobworker

test-integ:
	EASM_PG_DSN="$(EASM_APP_DSN)" $(GO) test ./... -count=1

backup: ## 全库快照（001–007 对象含 sweeps/auth_scopes 事实源；custom 格式可 pg_restore）
	@mkdir -p backups
	/opt/homebrew/opt/postgresql@18/bin/pg_dump -h 127.0.0.1 -U $(USER) -d easm -Fc -f backups/easm-$$(date +%Y%m%d-%H%M%S).dump
	@ls -t backups | head -1 | xargs -I{} echo "backup ok: backups/{}（保留最近 7 份可手动清理）"

