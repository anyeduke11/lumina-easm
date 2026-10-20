workspace "Lumina 烛隐 EASM" "当前态 C4 模型（基线 v0.0.2，2026-10-20）" {

    model {
        operator = person "安全运营人员" "执行排查、研判、处置、通报与报告；RBAC R1–R8" "Person"
        admin = person "平台管理员" "维护实体数据域、授权单、审计与配置；admin/R7" "Person"

        regulator = softwareSystem "公安 / 通报中心" "线索通报接收方；平台生成材料，人工投递后回填回执" "External"
        thirdParty = softwareSystem "第三方平台" "代码仓库 / 文档网盘 / 社交 / 暗市场；工单投诉与删除申请的目标" "External"
        feeds = softwareSystem "外部数据源" "crt.sh、DNS、ASM/Cloud feed、暗网 feed（当前为夹具形态）" "External"
        cli = softwareSystem "扫描 CLI 工具" "gitleaks / nmap / ffuf；以子进程执行，平台不内置扫描实现" "External"
        evidenceBackend = softwareSystem "证据存储" "本地文件或 MinIO/S3；WORM 语义，ref 可回溯" "External"
        idp = softwareSystem "OIDC 身份提供方" "RS256/JWKS；可选，未配置时仅 dev token / break-glass" "External,Optional"
        llm = softwareSystem "LLM Provider" "SenseNova / OpenAI 兼容；三件套同设才装配" "External,Optional"
        temporal = softwareSystem "Temporal" "可选工作流引擎；未配置时排查在 server 进程内同步执行" "External,Optional"
        sandbox = softwareSystem "沙箱验证服务" "可选门3 Provider（EASM_SANDBOX_URL）；未装配时复测端点 501" "External,Optional"

        lumina = softwareSystem "Lumina EASM 平台" "外部攻击面管理与互联网敏感信息泄露治理平台（模块化单体）" {
            console = container "静态控制台" "console/ 单页：app.js 演示数据 + easm-live.js 实时水化" "HTML/JavaScript"
            rest = container "REST API" "/v1/* 与 /healthz；集中路由注册；net/http" "Go"
            mcp = container "MCP 服务" "/mcp；JSON-RPC 2.0；只读/受控/高危三级工具" "Go"
            jobworker = container "Job Worker" "PG SKIP LOCKED 队列；发现、判敏与资产衰减" "Go"
            worker = container "Temporal Worker" "TaskQueue easm-sweep；执行排查活动" "Go"
            core = container "领域服务与装配根" "48 个 internal 包；cmd/server 手工装配 app.Deps" "Go"
            db = container "PostgreSQL" "关系事实源；部分表 RLS；schema_migrations 管理迁移" "PostgreSQL"
        }

        operator -> console "使用"
        admin -> console "管理"
        operator -> rest "Bearer / OIDC / break-glass"
        admin -> rest "Bearer / OIDC / break-glass"
        console -> rest "fetch /v1/*"
        rest -> core "鉴权 + Scope + 审计后调用域服务"
        mcp -> core "工具调用（与 REST 同闸）"
        jobworker -> core "发现与衰减任务"
        worker -> core "sweep.ExecuteInto"
        core -> db "SQL；事务内 set_config(easm.tenant_id)"
        core -> evidenceBackend "Put/Get（不可变对象）"
        core -> cli "exec.CommandContext"
        core -> feeds "HTTP / feed 拉取"
        core -> llm "Chat / 多模态（可选）"
        core -> temporal "调度（可选）"
        rest -> idp "Verify / JWKS（可选）"
        core -> sandbox "门3 复测（可选）"
        core -> operator "生成工单 / 通报材料 / 报告"
        operator -> thirdParty "线下投诉 / 删除申请、跟催"
        operator -> regulator "线下报送、取得回执"
        operator -> core "回填工单状态 / 通报回执"
    }

    views {
        systemContext lumina "SystemContext-当前态" {
            include *
            autolayout tb
        }

        container lumina "Container-当前态" {
            include *
            autolayout tb
        }

        styles {
            element "Person" {
                shape Person
                background "#08427b"
                color "#ffffff"
            }
            element "Container" {
                background "#438dd5"
                color "#ffffff"
            }
            element "External" {
                background "#8c8c8c"
                color "#ffffff"
            }
            element "Optional" {
                background "#d9d9d9"
                color "#595959"
            }
        }
    }
}
