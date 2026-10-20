// cmd/server 组装 EASM Go 主干（WP-M0-02/04 首切片：租户+RBAC+审计+资产 API）。
// M0 用内存存储与静态令牌打通契约；PG(RLS)/OIDC 在 WP-M0-03 完整版接入。
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/ai"
	"github.com/wangdev88/easm-platform/platform/services/internal/alert"
	"github.com/wangdev88/easm-platform/platform/services/internal/app"
	"github.com/wangdev88/easm-platform/platform/services/internal/asset"
	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/authn"
	"github.com/wangdev88/easm-platform/platform/services/internal/authz"
	"github.com/wangdev88/easm-platform/platform/services/internal/candidate"
	"github.com/wangdev88/easm-platform/platform/services/internal/classify"
	"github.com/wangdev88/easm-platform/platform/services/internal/collect"
	"github.com/wangdev88/easm-platform/platform/services/internal/config"
	"github.com/wangdev88/easm-platform/platform/services/internal/confirm"
	"github.com/wangdev88/easm-platform/platform/services/internal/connector"
	"github.com/wangdev88/easm-platform/platform/services/internal/darkweb"
	"github.com/wangdev88/easm-platform/platform/services/internal/detect"
	"github.com/wangdev88/easm-platform/platform/services/internal/discovery"
	"github.com/wangdev88/easm-platform/platform/services/internal/evalset"
	"github.com/wangdev88/easm-platform/platform/services/internal/evidence"
	"github.com/wangdev88/easm-platform/platform/services/internal/finding"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/httpapi"
	"github.com/wangdev88/easm-platform/platform/services/internal/ingest"
	"github.com/wangdev88/easm-platform/platform/services/internal/intel"
	"github.com/wangdev88/easm-platform/platform/services/internal/inventory"
	"github.com/wangdev88/easm-platform/platform/services/internal/job"
	"github.com/wangdev88/easm-platform/platform/services/internal/ledger"
	"github.com/wangdev88/easm-platform/platform/services/internal/mm"
	"github.com/wangdev88/easm-platform/platform/services/internal/monitor"
	"github.com/wangdev88/easm-platform/platform/services/internal/notice"
	"github.com/wangdev88/easm-platform/platform/services/internal/notify"
	"github.com/wangdev88/easm-platform/platform/services/internal/ownership"
	"github.com/wangdev88/easm-platform/platform/services/internal/pgstore"
	"github.com/wangdev88/easm-platform/platform/services/internal/plugin"
	"github.com/wangdev88/easm-platform/platform/services/internal/projection"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/report"
	"github.com/wangdev88/easm-platform/platform/services/internal/scoring"
	"github.com/wangdev88/easm-platform/platform/services/internal/secret"
	"github.com/wangdev88/easm-platform/platform/services/internal/shadowit"
	"github.com/wangdev88/easm-platform/platform/services/internal/sweep"
	"github.com/wangdev88/easm-platform/platform/services/internal/tdispatcher"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
	"github.com/wangdev88/easm-platform/platform/services/internal/usage"
	"github.com/wangdev88/easm-platform/platform/services/internal/verifier"
	"github.com/wangdev88/easm-platform/platform/services/internal/vuln"
	"github.com/wangdev88/easm-platform/platform/services/internal/workorder"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("配置装载失败（fail loud）: %v", err)
	}
	port := cfg.Port
	log.Printf("config: %s", cfg.Redacted())

	alog := audit.Log(&audit.MemLog{})

	var tstore tenant.Store = tenant.NewMemStore()
	var astore asset.Store = asset.NewMemStore()
	var lstore ledger.Store = ledger.NewMemStore() // M1 默认内存；PG 时替换（004_ledger.sql）
	var graphQuery httpapi.GraphQuery              // nil=图谱端点返回 501
	var pathQuery graph.PathQuery                  // M3-B：nil=路径端点 501（graph_path_unavailable）
	var graphSvc *graph.Service                    // M3-C：密钥判定的落图/读回面（图=事实源）
	backend := "memory"
	var assetSync func(ctx context.Context, a asset.Asset) error
	var kb *pgstore.KBStore    // 漏洞/情报持久层（005_knowledge.sql）；nil=纯内存
	var sweepStore sweep.Store // nil=内存（006）；PG 模式注入跨进程事实源（ENH-01）
	var authzStore authz.Store = authz.NewMemStore()
	var woStore workorder.Store = workorder.NewMemStore() // 011：处置工单（PG 模式替换，五态跟踪跨重启）
	var notStore notice.Store = notice.NewMemStore()      // 012：线索通报（PG 模式替换，CR-002 三要素跨重启锁定留存）
	var rptStore report.Store = report.NewMemStore()      // 013：报告历史（V-3 PG 化，对外交付物不随进程蒸发）
	var pgDB *pgstore.DB                                  // PG 句柄（008/009 端口装配）；nil=内存模式
	if cfg.PGDSN != "" {
		pg, err := pgstore.Open(cfg.PGDSN)
		if err != nil {
			log.Fatalf("EASM_PG_DSN 已设置但连接失败: %v", err)
		}
		pgDB = pg
		tstore, astore, lstore = pg.Tenants(), pg.Assets(), pg.Ledgers()
		kb = pg.KB()
		sweepStore = pg.Sweeps()  // 006
		authzStore = pg.Authz()   // 007：授权跨进程共享+重启不丢
		woStore = pg.WorkOrders() // 011：工单五态+留痕重启不丢
		notStore = pg.Notices()   // 012：通报三要素+回执重启不丢
		rptStore = pg.Reports()   // 013（V-3）：报告历史跨重启保留（对外交付物不随进程蒸发）
		backend = "postgres(RLS)"
		alog = pg.Audit() // NFR-SEC-006：审计仅追加落 PG
		gg := pg.Graph()  // MVP 图谱（PG 表实现）
		gs := graph.NewService(gg)
		graphSvc = gs
		assetSync = ingest.NewProjector(gs).Sync
		graphQuery = ingest.NewQueryService(gs, gg)
		pathQuery = pg.GraphPath() // M3-B：PG 递归 CTE 实现（与 MemPath 同端口、同排序契约）
	}

	// 内存模式图谱后端（M3-B 补齐）：此前内存模式无图谱（端点 501），
	// 与 PG 模式同口径——资产入账即投影为图谱实体，路径推演走内存 BFS。
	if pgDB == nil {
		gms := graph.NewMemStore()
		gs := graph.NewService(gms)
		graphSvc = gs
		assetSync = ingest.NewProjector(gs).Sync
		graphQuery = ingest.NewQueryService(gs, gms)
		pathQuery = graph.NewMemPath(gms)
	}

	// Phase 1 EASM 核心：资产身份/观察流、Finding、Job Queue、发现 Connector。
	var invStore inventory.Store = inventory.NewMemStore()
	var findStore finding.Store = finding.NewMemStore()
	var jobStore job.Store = job.NewMemStore()
	var alertStore alert.Store = alert.NewMemStore()
	if pgDB != nil {
		invStore, findStore, jobStore, alertStore = pgDB.Inventory(), pgDB.Findings(), pgDB.Jobs(), pgDB.Alerts()
	}
	invSvc := inventory.New(invStore, alog)
	findSvc := finding.New(findStore, alog)
	jobSvc := job.New(jobStore, alog)
	alertSvc := alert.New(alertStore, alog)
	detSvc := detect.New(findSvc).WithAlerts(alertSvc)
	connReg := connector.NewRegistry()
	if err := connReg.Register(connector.Seed{}); err != nil {
		log.Fatalf("connector seed 注册失败: %v", err)
	}
	if err := connReg.Register(connector.NewCT()); err != nil {
		log.Fatalf("connector ct 注册失败: %v", err)
	}
	if err := connReg.Register(connector.NewDNS()); err != nil {
		log.Fatalf("connector dns 注册失败: %v", err)
	}
	if cfg.ASMURL != "" {
		asm, err := connector.NewASM(cfg.ASMURL, cfg.ASMToken)
		if err != nil {
			log.Fatalf("connector asm 配置失败: %v", err)
		}
		if err := connReg.Register(asm); err != nil {
			log.Fatalf("connector asm 注册失败: %v", err)
		}
		log.Printf("connector: asm enabled url=%s", cfg.ASMURL)
	}
	if cfg.CloudURL != "" {
		cloud, err := connector.NewCloud(cfg.CloudURL, cfg.CloudToken)
		if err != nil {
			log.Fatalf("connector cloud 配置失败: %v", err)
		}
		if err := connReg.Register(cloud); err != nil {
			log.Fatalf("connector cloud 注册失败: %v", err)
		}
		log.Printf("connector: cloud enabled url=%s", cfg.CloudURL)
	}
	discSvc := discovery.New(invSvc, graphSvc, jobSvc, connReg).WithAudit(alog).WithFindings(findSvc).WithDetector(detSvc)

	tsvc := tenant.NewService(tstore, alog)
	asvc := asset.NewService(astore, alog)
	if assetSync != nil {
		asvc.SetAssetSync(assetSync) // WP-M0-06：入账资产投影为图谱实体（FR-DSC-012；失败补偿回滚）
	}
	// 风险台账（F4）
	ledSvc := ledger.NewService(lstore, alog)
	projSvc := projection.New(ledSvc)
	// 门3 沙箱复测 provider（ENH-10 前端接缝）：EASM_SANDBOX_URL 装载外部沙箱服务——
	// 隔离微 VM 池/interactsh 回连/非破坏性（NFR-SEC-010）/证据 WORM/高危人工审批（AX-5）
	// 由沙箱服务侧承担；平台侧对回执做同等硬闸（verifier 包）。
	// 未设置时 method=sandbox 返回 501（fail loud，禁止造假闭环）；manual/cross_tool 不受影响。
	if sbURL := cfg.SandboxURL; sbURL != "" {
		sb, err := verifier.NewSandbox(sbURL)
		if err != nil {
			log.Fatalf("沙箱 provider 装载失败: %v", err)
		}
		ledSvc.SetVerifier(sb.VerifyItem)
		log.Printf("sandbox verifier endpoint=%s（ENH-10 前端接缝；沙箱本体前置由服务侧承担）", sbURL)
	}
	// 五阶段工作流（F2/FR-DSC）：进程内顺序执行近似（ENH-01 接管后切 Temporal）。
	sweepSvc := sweep.NewService(astore, classify.New(), ledSvc)
	if sweepStore != nil {
		sweepSvc.SetStore(sweepStore) // ENH-01：sweep 行落 PG（worker/server 跨进程共享）
	}
	// 授权范围（FR-DSC-013 / 一票否决⑥）+ 插件注册中心（FR-PLG）
	authzSvc := authz.NewService(authzStore, alog)
	sweepSvc.SetScope(authzSvc)    // 无有效 scope 的租户不得执行排查
	sweepSvc.WithLimiter(authzSvc) // S-1：编排层消费 scope.rate_limit（步间最小间隔+执行行留痕）
	plugins := plugin.NewRegistry()
	// ENH-01 编排派发器（配置 EASM_TEMPORAL_HOST 即装载；未配置=进程内回退，接缝不变）
	var dispatcher httpapi.SweepDispatcher
	if host := cfg.TemporalHost; host != "" {
		d, err := tdispatcher.New(host)
		if err != nil {
			log.Fatalf("EASM_TEMPORAL_HOST=%s 已设置但连接失败（fail loud，拒绝静默回退）: %v", host, err)
		}
		dispatcher = d
		defer d.Close()
		log.Printf("ENH-01 已启用：sweep 经 Temporal 派发 queue=%s", tdispatcher.TaskQueue)
	}
	// 知识库（F9）与归属判定（FR-DSC-010 规则版）
	vulnSvc, intelSvc, ownSvc := vuln.NewService(), intel.NewService(), ownership.NewService()
	if kb != nil { // 落 PG：seed 写穿 + DB 真源 hydrate（跨重启不丢导入条目）
		if err := vulnSvc.AttachStore(kb); err != nil {
			log.Fatalf("漏洞库接 PG 失败（fail loud，拒绝半可用）: %v", err)
		}
		if err := intelSvc.AttachStore(kb); err != nil {
			log.Fatalf("情报库接 PG 失败: %v", err)
		}
	}

	// 监测预警（F14 近似）：调度 provider 用平台主体全量视角（等同 R7 穿透）；
	// 请求级端点仍按主体作用域过滤（httpapi.scopeAssets）。
	monSvc := monitor.New(vulnSvc, intelSvc, func() map[string][]asset.Asset {
		out := map[string][]asset.Asset{}
		ts, err := tsvc.List(context.Background(), monitorPrincipal)
		if err != nil {
			log.Printf("monitor: 租户列举失败: %v", err)
			return out
		}
		for _, t := range ts {
			if l, _ := asvc.ListByTenant(context.Background(), monitorPrincipal, "mon", t.ID); len(l) > 0 {
				out[t.ID] = l
			}
		}
		return out
	})
	monSvc.Start(context.Background())
	if pgDB != nil {
		monSvc.SetSnapStore(pgDB.Snapshots())       // 008：FR-MON-002 diff 基线跨扫描持久
		monSvc.AttachTaskStore(pgDB.MonitorTasks()) // 021：FR-MON-003 排查任务单跨重启可查
	}
	// 告警统一出口（F14.4）：通道经 env 配置；G8-02 前仅内部/自管渠道（webhook 含钉钉/飞书机器人形态）
	notiSvc := notify.New()
	if u := cfg.AlertWebhook; u != "" {
		notiSvc.AddChannel("webhook", notify.Webhook(u))
	}
	if to := cfg.AlertMailTo; to != "" {
		notiSvc.AddChannel("mail", notify.SMTPSender(cfg.AlertMailFrom, to, nil))
	}
	// M4-04 SOAR 联动通道：URL+密钥同设才装配；单设=配置不完整 fail loud（拒绝半可用）。
	if u, sec := cfg.SOARWebhook, cfg.SOARSecret; u != "" || sec != "" {
		if u == "" || sec == "" {
			log.Fatalf("EASM_SOAR_WEBHOOK 与 EASM_SOAR_SECRET 必须同设（HMAC 验签缺一不可）")
		}
		notiSvc.AddChannel("soar", notify.SOAR(u, sec))
	}
	if pgDB != nil {
		if err := notiSvc.AttachLog(pgDB.NotifyLog()); err != nil { // 009：跨重启去重+留痕
			log.Fatalf("notify 历史接 PG 失败: %v", err)
		}
	}
	alertSvc.WithNotifier(notiSvc).WithAutoDispatch(true)

	// M4-07：AI 面计量与预算（FR-HRN-10 P1）——事件/预算落 PG（022，未装 PG=进程内回退）；
	// 预算告警经 notify 统一出口（通道未配置=告警仅状态可见，如实标注不冒充管控）。
	var usageStore usage.Store = usage.NewMemStore()
	if pgDB != nil {
		usageStore = pgDB.Usage()
	}
	usageSvc := usage.New(usageStore).WithSink(func(ctx context.Context, a usage.Alert) error {
		ma := monitor.Alert{Kind: a.Kind, Key: a.Key, TenantID: a.TenantID,
			Severity: "medium", Msg: a.Msg, TS: time.Now().UTC()}
		_, _, err := notiSvc.Dispatch(ctx, "webhook", []monitor.Alert{ma})
		return err
	})

	// 证据对象存储（ENH-05）：EASM_EVIDENCE=minio 装载 MinIO/S3；默认 file=本地文件（MVP 过渡形态）。
	// 接缝不变（evidence.Store），Provider 由 env 切换（设计方案 §4.2）；装载失败一律 fail loud。
	var evidSvc evidence.Store
	switch mode := cfg.EvidenceMode; mode {
	case "minio":
		st, err := evidence.NewMinIOStore(cfg.MinioEndpoint, cfg.MinioAK, cfg.MinioSK,
			cfg.MinioBucket, cfg.MinioSSL)
		if err != nil {
			log.Fatalf("证据存储 minio 装载失败（fail loud，拒绝静默降级）: %v", err)
		}
		evidSvc = st
		log.Printf("evidence backend=minio endpoint=%s bucket=%s", cfg.MinioEndpoint, cfg.MinioBucket)
	case "file":
		st, err := evidence.NewFileStore(cfg.EvidenceDir)
		if err != nil {
			log.Fatalf("证据存储 file 装载失败: %v", err)
		}
		evidSvc = st
		log.Printf("evidence backend=file root=%s（MVP 过渡；ENH-05 正式形态=minio）", cfg.EvidenceDir)
	default:
		log.Fatalf("EASM_EVIDENCE 非法取值：%q（须 file|minio）", mode)
	}

	// 门3 简单隔离复测（ENH-10 过渡形态，用户决策 2026-10-18：沙箱本体暂不需要）：
	// EASM_VERIFY_CMD 装载本机复测命令——ulimit 文件空间 + nice 优先级 + 超时 + 一次性工作区，
	// 产物入 evidence WORM（C-5）。与 EASM_SANDBOX_URL 互斥（HTTP provider 优先，先到先得）。
	// 复测契约：<cmd> <item_id> <tenant> <workdir>，工作区写 result.txt（reproduced|refuted|inconclusive）。
	if cfg.SandboxURL == "" {
		if vcmd := cfg.VerifyCmd; vcmd != "" {
			lv, err := verifier.NewLocal(vcmd, cfg.VerifyWorkspace, evidSvc,
				verifier.WithFSizeMB(cfg.VerifyFSizeMB),
				verifier.WithNice(cfg.VerifyNice),
				verifier.WithTimeout(cfg.VerifyTimeout))
			if err != nil {
				log.Fatalf("简单隔离复测 provider 装载失败（fail loud）: %v", err)
			}
			ledSvc.SetVerifier(lv.VerifyItem)
			log.Printf("verifier=local cmd=%s（简单隔离：ulimit 文件空间+nice 优先级+超时；ENH-10 正式形态就绪后切 EASM_SANDBOX_URL）", vcmd)
		}
	}

	tokens := parseTokens(cfg.DevTokens)
	if cfg.SingleUser {
		if cfg.DevTokens == "" && cfg.OIDCIssuer == "" {
			log.Fatalf("EASM_SINGLE_USER=1 需要 EASM_DEV_TOKENS 或 OIDC（否则无人可登录）")
		}
		if cfg.DevTokens != "" {
			var err error
			tokens, err = singleUserTokens(tokens)
			if err != nil {
				log.Fatalf("EASM_SINGLE_USER=1 配置非法（fail loud）: %v", err)
			}
			log.Printf("single-user mode: 1 operator token, role=admin（多用户 RBAC 不对外暴露；entity 数据域仍按 tenant/RLS 隔离）")
		}
	}
	if len(tokens) == 0 && cfg.OIDCIssuer == "" {
		log.Printf("warn: EASM_DEV_TOKENS 未设置，所有请求将 401（仅影响 dev，见 Makefile run 目标）")
	}
	// V-8 dev 令牌能力边界（ENH-07 OIDC 未接入期间的显式声明，禁止静默）：
	// 静态 bearer 令牌=无过期/无作用域/无吊销，仅适用内网或离线验证环境；
	// 对外多租户接入前必须替换为 OIDC（ENH-07），生产环境直接拒绝启动（fail loud）。
	if len(tokens) > 0 {
		if cfg.Env == "production" {
			log.Fatalf("EASM_ENV=production 禁用 dev 静态令牌（EASM_DEV_TOKENS）：无过期/无吊销/无作用域，对外环境必须走 OIDC（ENH-07）")
		}
		log.Printf("warn: dev 静态令牌已启用（%d 枚，ENH-07 OIDC 未接入）——能力边界：无过期/无吊销/无作用域，仅限内网或离线验证；对外多租户接入前必须替换为 OIDC", len(tokens))
	}

	candSvc := candidate.NewService()                                  // WP-M1-05 契约（M2 前置）；MVP 内存队列，PG 化随 M2-01
	colSvc := collect.New(candSvc, ledSvc, authzSvc, evidSvc, nil)     // M2-01 渠道 repo.secret/SCAN-1/SCAN-2
	colSvc.WithLimiter(authzSvc)                                       // rate_limit→工具参数消费（K3 条件②闭合）
	darkSvc := darkweb.New(candSvc, ledSvc, authzSvc, ownSvc, evidSvc) // M2-02 暗网兜底/线索包（归属指纹消费 FR-CHN-005）
	woSvc := workorder.NewService(woStore, alog, ledSvc)               // M2-03 处置工单（建单挂账=ledger 读口闸）
	notSvc := notice.NewService(notStore, alog, ledSvc)                // M2-04 线索通报（CR-002 三要素；材料固化证据）
	notSvc.WithLedgerList(ledSvc)                                      // 合规总结的台账统计面（FR-LGR-008/FR-RPT-005）
	notSvc.WithEvidence(evidSvc)
	rptSvc := report.NewService(rptStore, alog, tsvc, ledSvc) // M2-09 报告中心（历史：PG 模式=013 持久，内存模式=MemStore 同契约）
	rptSvc.WithAssets(asvc)
	rptSvc.WithPackages(darkSvc)
	rptSvc.WithWorkOrders(woSvc)
	rptSvc.WithNotices(notSvc)
	rptSvc.WithEvidence(evidSvc)
	if pgDB != nil { // 010：基线水化+写穿 / 线索包跨重启可检索（fail loud 拒绝半装配）
		if err := ownSvc.AttachFPStore(context.Background(), pgDB.Darkweb()); err != nil {
			log.Fatalf("指纹基线接 PG 失败（fail loud，重启后判据不可丢）: %v", err)
		}
		darkSvc.AttachStore(pgDB.Darkweb())
		// V-4：人工复核面落 PG——疑似/无关样本队列 + 被拒候选行，都是「不静默丢弃」的
		// fail-loud 锚点，重启即蒸发等于把问题悄悄扔掉（水化/写穿失败一律拒绝半装配）。
		if err := ownSvc.AttachQueueStore(context.Background(), pgDB.OwnershipQueue()); err != nil {
			log.Fatalf("归属复核队列接 PG 失败（fail loud，复核锚点不可丢）: %v", err)
		}
		if err := candSvc.AttachStore(context.Background(), pgDB.Candidates()); err != nil {
			log.Fatalf("候选 unsupported 队列接 PG 失败（fail loud，复核锚点不可丢）: %v", err)
		}
		// V-9：accepted 摄取留痕接 PG——「摄取过什么」可追溯（与 unsupported 一进一出同口径）
		if err := candSvc.AttachAcceptedStore(context.Background(), pgDB.Candidates()); err != nil {
			log.Fatalf("候选 accepted 留痕接 PG 失败（fail loud，摄取历史不可丢）: %v", err)
		}
	}

	// M3-C：密钥有效性验证（FR-CHN-002）——图谱即事实源（判定入图、度量读回，
	// 度量不随进程蒸发）；外呼**默认关闭**，仅 EASM_SECRET_PROBE=1 显式开启时
	// 才对请求方显式给出的目标发起非破坏 GET（AX-5 人在环，不自行推断外呼目标）。
	secretSvc := secret.New().WithGraph(graphSvc)
	if cfg.SecretProbe {
		secretSvc = secretSvc.WithProber(secret.NewHTTPProber(8*time.Second, nil).
			WithPrivateTargets(cfg.SecretProbePrivate))
	}
	// M3-C：影子 IT 收敛建议与纳管人审面（FR-MIN-003；与主链路共用同一归属判定实例）
	shadowSvc := shadowit.New(ownSvc)

	// M3-E：评测集与反馈门禁（WP-M3-06 / FR-VRF-004 / AIL-7）——样本与运行记录落 PG
	// （019，跨重启可查）；门禁阈值经 EASM_EVAL_THRESHOLDS 注入（非法装载即拒 fail loud；
	// 未设置=登记口径默认值并在 API 标注「待 G8-01 定稿」）。
	var evalStore evalset.Store = evalset.NewMemStore()
	if pgDB != nil {
		evalStore = pgDB.EvalSet()
	}
	evalSvc := evalset.New(evalStore)
	if raw := cfg.EvalThresholds; raw != "" {
		th, err := evalset.ParseThresholds(raw)
		if err != nil {
			log.Fatalf("EASM_EVAL_THRESHOLDS 非法: %v", err)
		}
		evalSvc = evalSvc.WithThresholds(th)
	}

	// ENH-03：AI 推理面接缝（Provider=SenseNova，OpenAI 兼容 chat；后续内网模型等
	// 实现同一 ai.Provider 接口替换装配，上层零改动）。三件套（BASE_URL/MODEL/API_KEY）
	// 须同设才装配；任一设置而 API_KEY 缺失=fail loud（拒绝半可用）；全未设=能力边界
	// （mm:analyze / shadow with_ai 返 501，不静默降级）。密钥只走 env，不落日志不落代码。
	var aiProv ai.Provider
	if cfg.AIAPIKey != "" {
		aiCfg := ai.Config{BaseURL: cfg.AIBaseURL, Model: cfg.AIModel, APIKey: cfg.AIAPIKey}
		if err := aiCfg.Validate(); err != nil {
			log.Fatalf("EASM_AI_* 配置非法: %v", err)
		}
		p, err := ai.NewSenseNova(aiCfg, 60*time.Second)
		if err != nil {
			log.Fatalf("AI provider 装载失败: %v", err)
		}
		aiProv = p
		log.Printf("ENH-03 AI 面已装配 provider=sensenova model=%s（M3-D 多模态判敏 + M3-C-AI 文案）", aiCfg.Model)
	}
	// M3-D 多模态判敏（AIL-5/6：富化结果进图谱且可解释；AI 结论不入台账）。
	mmSvc := mm.New(aiProv, graphSvc)
	if aiProv != nil {
		shadowSvc = shadowSvc.WithAI(aiProv) // M3-C-AI：建议文案接缝（红线由域层保证）
	}
	mmSvc.SetUsage(usageSvc)                  // M4-07：mm 判敏按租户计量
	shadowSvc = shadowSvc.WithUsage(usageSvc) // M4-07：with_ai 文案按租户计量

	// 单用户高危动作确认（FR-LGR-005/CR-001/AX-5）：PG 模式落库，内存模式回退。
	// 默认开启：scan.port/scan.dir/notice.create 必须携带 X-EASM-Confirmation（REST/MCP 同闸）；
	// 仅以 EASM_REQUIRE_CONFIRMATION=0 显式降级。
	var confirmStore confirm.Store = confirm.NewMemStore()
	if pgDB != nil {
		confirmStore = pgDB.Confirmations()
	}
	confirmSvc := confirm.New(confirmStore, alog)
	confirmRequired := cfg.RequireConfirmation
	if confirmRequired {
		log.Printf("single-user confirmation: required for scan.port/scan.dir/notice.create")
	}

	// OIDC / break-glass：OIDC 三件套已由 config 校验；break-glass 只存 hash。
	var oidc *authn.OIDC
	if cfg.OIDCIssuer != "" {
		oidc, err = authn.NewOIDC(cfg.OIDCIssuer, cfg.OIDCAudience, cfg.OIDCJWKSURL)
		if err != nil {
			log.Fatalf("OIDC 装载失败（fail loud）: %v", err)
		}
		log.Printf("authn: OIDC enabled issuer=%s audience=%s", cfg.OIDCIssuer, cfg.OIDCAudience)
	}
	var bg *authn.BreakGlass
	if cfg.BreakGlassHash != "" {
		bg, err = authn.NewBreakGlass(cfg.BreakGlassHash, alog)
		if err != nil {
			log.Fatalf("break-glass 装载失败（fail loud）: %v", err)
		}
		log.Printf("authn: break-glass enabled（每次使用写审计）")
	}
	var pk *authn.Passkey
	if cfg.PasskeyPublicKey != "" {
		pk, err = authn.NewPasskey(cfg.PasskeyPublicKey)
		if err != nil {
			log.Fatalf("passkey 装载失败（fail loud）: %v", err)
		}
		log.Printf("authn: passkey enabled（ES256 challenge-response；WebAuthn 为 Provider 替换）")
	}

	// M3-A 评分口径（FR-MIN-001/002）：配置注入权重/阈值；非法即 fail loud。
	scoreW, scoreTh := scoring.DefaultWeights(), scoring.DefaultThresholds()
	if raw := cfg.ScoreWeights; raw != "" {
		w, err := scoring.ParseWeights(raw)
		if err != nil {
			log.Fatalf("EASM_SCORE_WEIGHTS 非法: %v", err)
		}
		scoreW = w
	}
	if raw := cfg.ScoreThresholds; raw != "" {
		th, err := scoring.ParseThresholds(raw)
		if err != nil {
			log.Fatalf("EASM_SCORE_THRESHOLDS 非法: %v", err)
		}
		scoreTh = th
	}

	// /readyz 真实依赖探活：PG 模式 Ping 数据库；内存模式无外部依赖（nil=ready）。
	var ready func(context.Context) error
	if pgDB != nil {
		ready = pgDB.Ping
	}

	srv := &http.Server{
		Addr: ":" + port,
		Handler: app.Deps{
			Tenants: tsvc, Assets: asvc, Ledger: ledSvc, Sweep: sweepSvc, Authz: authzSvc,
			Plugins: plugins, Vuln: vulnSvc, Intel: intelSvc, Ownership: ownSvc, Monitor: monSvc,
			Notify: notiSvc, Evidence: evidSvc, Candidate: candSvc, Collect: colSvc,
			Darkweb: darkSvc, WorkOrder: woSvc, Notice: notSvc, Report: rptSvc,
			Dispatcher: dispatcher, Tokens: tokens, GraphQuery: graphQuery, PathQuery: pathQuery,
			Secret: secretSvc, Shadow: shadowSvc, Eval: evalSvc, MM: mmSvc, Usage: usageSvc,
			Confirm: confirmSvc, ConfirmRequired: confirmRequired,
			OIDC: oidc, BreakGlass: bg, Passkey: pk,
			Inventory: invSvc, Findings: findSvc, Jobs: jobSvc, Discovery: discSvc, Projection: projSvc, Alerts: alertSvc, Detector: detSvc,
			AssetStale: cfg.AssetStaleAfter, AssetRetire: cfg.AssetRetireAfter,
			ScoreWeights: scoreW, ScoreThresholds: scoreTh,
			Audit: alog, ConsoleDir: cfg.ConsoleDir, Ready: ready,
		}.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	log.Printf("easm services listening on :%s backend=%s (dev tokens=%d)", port, backend, len(tokens))
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	case <-ctx.Done():
		log.Printf("shutdown: 收到退出信号，停止接收新请求（超时 10s）")
		sdCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(sdCtx); err != nil {
			log.Printf("shutdown: 优雅停机失败（强制退出）: %v", err)
		}
		if pgDB != nil {
			if err := pgDB.Close(); err != nil {
				log.Printf("shutdown: 关闭 PG 连接池失败: %v", err)
			}
		}
		log.Printf("shutdown: 已退出")
	}
}

// monitorPrincipal 调度器系统主体（等同 R7 全量视角；仅用于 provider 取数，
// 请求级端点仍按请求主体过滤）。
var monitorPrincipal = rbac.Principal{UserID: "monitor-scheduler", Role: "R7", TenantIDs: []string{"*"}}

// parseTokens 解析 "token:role:t1|t2,token2:R7:*"。仅供 dev；生产走 OIDC（NFR-SEC-002）。
func parseTokens(spec string) map[string]rbac.Principal {
	out := map[string]rbac.Principal{}
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, ":", 3)
		if len(parts) != 3 {
			continue
		}
		var tenants []string
		if parts[2] != "*" {
			tenants = strings.Split(parts[2], "|")
		} else {
			tenants = []string{"*"}
		}
		out[parts[0]] = rbac.Principal{UserID: "dev-" + parts[0], Role: parts[1], TenantIDs: tenants}
	}
	return out
}

// singleUserTokens 单用户监管形态：恰好一枚操作员令牌，角色固定 admin。
// 多用户 RBAC 保留在内部作为纵深防御，但不对外暴露多账号入口。
func singleUserTokens(in map[string]rbac.Principal) (map[string]rbac.Principal, error) {
	if len(in) != 1 {
		return nil, fmt.Errorf("EASM_SINGLE_USER=1 要求恰好一枚 EASM_DEV_TOKENS（当前 %d 枚）；单用户模式不暴露多账号", len(in))
	}
	out := make(map[string]rbac.Principal, 1)
	for k, p := range in {
		p.Role = "admin"
		p.TenantIDs = []string{"*"}
		out[k] = p
	}
	return out, nil
}
