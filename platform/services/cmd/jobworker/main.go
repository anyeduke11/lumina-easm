// Package main 是 Phase 1/2 发现与判敏 Job Worker 入口（FR-DSC/FR-CLS/执行平面）。
//
// 独立进程消费 jobs 表（SKIP LOCKED 租约），执行 connector -> observation ->
// 资产身份/图谱投影。与 HTTP 进程解耦，可多实例水平扩展。
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/alert"
	"github.com/wangdev88/easm-platform/platform/services/internal/config"
	"github.com/wangdev88/easm-platform/platform/services/internal/connector"
	"github.com/wangdev88/easm-platform/platform/services/internal/detect"
	"github.com/wangdev88/easm-platform/platform/services/internal/discovery"
	"github.com/wangdev88/easm-platform/platform/services/internal/finding"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/inventory"
	"github.com/wangdev88/easm-platform/platform/services/internal/job"
	"github.com/wangdev88/easm-platform/platform/services/internal/notify"
	"github.com/wangdev88/easm-platform/platform/services/internal/pgstore"
	"github.com/wangdev88/easm-platform/platform/services/internal/rbac"
	"github.com/wangdev88/easm-platform/platform/services/internal/tenant"
)

func main() {
	once := flag.Bool("once", false, "只跑一轮后退出（运维/测试）")
	owner := flag.String("owner", "", "worker 标识（默认 hostname-pid）")
	interval := flag.Duration("interval", 2*time.Second, "轮询间隔")
	limit := flag.Int("limit", 10, "单轮最多领取任务数")
	decayEvery := flag.Duration("decay-every", 10*time.Minute, "资产衰减扫描间隔（0=关闭）")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if cfg.PGDSN == "" {
		log.Fatal("jobworker 需要 EASM_PG_DSN（持久队列）")
	}
	db, err := pgstore.Open(cfg.PGDSN)
	if err != nil {
		log.Fatalf("PG 连接失败: %v", err)
	}
	graphSvc := graph.NewService(db.Graph())
	invSvc := inventory.New(db.Inventory(), db.Audit())
	findSvc := finding.New(db.Findings(), db.Audit())
	alertSvc := alert.New(db.Alerts(), db.Audit())
	notiSvc := notify.New()
	if cfg.AlertWebhook != "" {
		notiSvc.AddChannel("webhook", notify.Webhook(cfg.AlertWebhook))
	}
	if cfg.AlertMailTo != "" {
		notiSvc.AddChannel("mail", notify.SMTPSender(cfg.AlertMailFrom, cfg.AlertMailTo, nil))
	}
	if cfg.SOARWebhook != "" {
		notiSvc.AddChannel("soar", notify.SOAR(cfg.SOARWebhook, cfg.SOARSecret))
	}
	if err := notiSvc.AttachLog(db.NotifyLog()); err != nil {
		log.Fatalf("notify history: %v", err)
	}
	alertSvc.WithNotifier(notiSvc).WithAutoDispatch(true)
	jobSvc := job.New(db.Jobs(), db.Audit())
	tenantSvc := tenant.NewService(db.Tenants(), db.Audit())
	reg := connector.NewRegistry()
	if err := reg.Register(connector.Seed{}); err != nil {
		log.Fatalf("register seed: %v", err)
	}
	if err := reg.Register(connector.NewCT()); err != nil {
		log.Fatalf("register ct: %v", err)
	}
	if err := reg.Register(connector.NewDNS()); err != nil {
		log.Fatalf("register dns: %v", err)
	}
	if cfg.ASMURL != "" {
		asm, err := connector.NewASM(cfg.ASMURL, cfg.ASMToken)
		if err != nil {
			log.Fatalf("asm config: %v", err)
		}
		if err := reg.Register(asm); err != nil {
			log.Fatalf("register asm: %v", err)
		}
	}
	if cfg.CloudURL != "" {
		cloud, err := connector.NewCloud(cfg.CloudURL, cfg.CloudToken)
		if err != nil {
			log.Fatalf("cloud config: %v", err)
		}
		if err := reg.Register(cloud); err != nil {
			log.Fatalf("register cloud: %v", err)
		}
	}
	svc := discovery.New(invSvc, graphSvc, jobSvc, reg).WithAudit(db.Audit()).WithFindings(findSvc).WithDetector(detect.New(findSvc).WithAlerts(alertSvc))

	id := *owner
	if id == "" {
		host, _ := os.Hostname()
		id = host + "-" + time.Now().UTC().Format("150405")
	}
	w := discovery.NewWorker(svc, jobSvc, id).WithInterval(*interval)

	if *once {
		n, err := w.RunOnce(context.Background(), *limit)
		if err != nil {
			log.Fatalf("run once: %v", err)
		}
		if *decayEvery > 0 {
			decayAll(context.Background(), invSvc, tenantSvc, cfg.AssetStaleAfter, cfg.AssetRetireAfter)
		}
		log.Printf("jobworker: %d jobs done", n)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("jobworker: owner=%s interval=%s", id, *interval)
	if *decayEvery > 0 {
		go func() {
			decayAll(ctx, invSvc, tenantSvc, cfg.AssetStaleAfter, cfg.AssetRetireAfter)
			t := time.NewTicker(*decayEvery)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					decayAll(ctx, invSvc, tenantSvc, cfg.AssetStaleAfter, cfg.AssetRetireAfter)
				}
			}
		}()
	}
	w.Run(ctx)
}

func decayAll(ctx context.Context, inv *inventory.Service, tenants *tenant.Service, stale, retire time.Duration) {
	p := rbac.Principal{UserID: "asset-decay", Role: "admin", TenantIDs: []string{"*"}}
	ts, err := tenants.List(ctx, p)
	if err != nil {
		log.Printf("asset decay: list entities: %v", err)
		return
	}
	for _, t := range ts {
		n, err := inv.Decay(ctx, t.ID, stale, retire, "asset-decay")
		if err != nil {
			log.Printf("asset decay: %s: %v", t.ID, err)
			continue
		}
		if n > 0 {
			log.Printf("asset decay: %s: %d assets updated", t.ID, n)
		}
	}
}
