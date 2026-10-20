// Package discovery 编排发现 Connector、资产身份归并与 Exposure Graph 投影（Phase 1 / FR-DSC-012）。
package discovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/connector"
	"github.com/wangdev88/easm-platform/platform/services/internal/detect"
	"github.com/wangdev88/easm-platform/platform/services/internal/finding"
	"github.com/wangdev88/easm-platform/platform/services/internal/graph"
	"github.com/wangdev88/easm-platform/platform/services/internal/inventory"
	"github.com/wangdev88/easm-platform/platform/services/internal/job"
)

var ErrInvalid = errors.New("discovery: invalid request")

type Result struct {
	JobID        string `json:"job_id"`
	Connector    string `json:"connector"`
	Observations int    `json:"observations"`
	Assets       int    `json:"assets"`
	Created      int    `json:"created"`
	Findings     int    `json:"findings"`
}

type Service struct {
	inv      *inventory.Service
	graph    *graph.Service
	jobs     *job.Service
	findings *finding.Service
	detector *detect.Detector
	reg      *connector.Registry
	log      audit.Log
	now      func() time.Time
}

func New(inv *inventory.Service, g *graph.Service, jobs *job.Service, reg *connector.Registry) *Service {
	return &Service{inv: inv, graph: g, jobs: jobs, reg: reg, now: time.Now}
}

func (s *Service) WithAudit(l audit.Log) *Service { s.log = l; return s }

// WithFindings 允许 Connector 通过 Observation.Finding 产出 Finding。
func (s *Service) WithFindings(f *finding.Service) *Service { s.findings = f; return s }

// WithDetector 对每个观察执行确定性判敏并自动创建 Finding。
func (s *Service) WithDetector(d *detect.Detector) *Service { s.detector = d; return s }

// Enqueue 入队一次发现任务；connector 必须已注册（白名单）。
func (s *Service) Enqueue(ctx context.Context, entityID, connectorName string, seeds []string) (job.Job, error) {
	if strings.TrimSpace(entityID) == "" || strings.TrimSpace(connectorName) == "" {
		return job.Job{}, fmt.Errorf("%w: entity_id / connector 必填", ErrInvalid)
	}
	if s.reg == nil {
		return job.Job{}, fmt.Errorf("%w: connector registry 未装配", ErrInvalid)
	}
	if _, ok := s.reg.Get(connectorName); !ok {
		return job.Job{}, fmt.Errorf("%w: 未注册 connector %q", ErrInvalid, connectorName)
	}
	if s.jobs == nil {
		return job.Job{}, fmt.Errorf("%w: job service 未装配", ErrInvalid)
	}
	return s.jobs.Enqueue(ctx, job.Job{
		EntityID: entityID, Kind: "discovery",
		Payload: map[string]any{"connector": connectorName, "seeds": seeds},
	})
}

// RunJob 执行一个 discovery job：Connector -> Observation -> Asset/别名/观察 -> 图谱。
func (s *Service) RunJob(ctx context.Context, j job.Job) (Result, error) {
	if j.Kind != "discovery" {
		return Result{}, fmt.Errorf("%w: 非 discovery job %q", ErrInvalid, j.Kind)
	}
	name, _ := j.Payload["connector"].(string)
	seeds := toStrings(j.Payload["seeds"])
	if s.reg == nil || name == "" {
		return Result{}, fmt.Errorf("%w: 未注册 connector", ErrInvalid)
	}
	c, ok := s.reg.Get(name)
	if !ok {
		return Result{}, fmt.Errorf("%w: 未注册 connector %q", ErrInvalid, name)
	}
	obs, err := c.Run(ctx, connector.Input{EntityID: j.EntityID, Seeds: seeds})
	if err != nil {
		return Result{}, err
	}
	res := Result{JobID: j.ID, Connector: name, Observations: len(obs)}
	seen := map[string]bool{}
	for _, o := range obs {
		a, created, err := s.inv.Ingest(ctx, j.EntityID, inventory.Observation{
			Kind: o.Kind, Value: o.Value, SourceID: o.SourceID,
			RawRef: o.RawRef, Payload: o.Payload, ObservedAt: o.ObservedAt,
		})
		if err != nil {
			return res, fmt.Errorf("ingest %s: %w", o.Value, err)
		}
		if seen[a.ID] {
			continue
		}
		seen[a.ID] = true
		res.Assets++
		if created {
			res.Created++
		}
		if err := s.project(ctx, j.EntityID, a, o); err != nil {
			return res, err
		}
		if s.detector != nil {
			detected, err := s.detector.Observe(ctx, a, inventory.Observation{
				Kind: o.Kind, Value: o.Value, SourceID: o.SourceID,
				RawRef: o.RawRef, Payload: o.Payload, ObservedAt: o.ObservedAt,
			})
			if err != nil {
				return res, err
			}
			res.Findings += len(detected)
		}
		if o.Finding != nil && s.findings != nil {
			var ev []string
			if strings.TrimSpace(o.Finding.EvidenceRef) != "" {
				ev = []string{o.Finding.EvidenceRef}
			}
			_, err := s.findings.Create(ctx, finding.Finding{
				EntityID: j.EntityID, AssetID: a.ID, Type: o.Finding.Type,
				Title: o.Finding.Title, Severity: o.Finding.Severity,
				Confidence: o.Finding.Confidence, Source: o.SourceID,
				RuleID: o.Finding.RuleID, EvidenceRefs: ev,
			})
			if err != nil {
				return res, fmt.Errorf("finding %s: %w", o.Finding.Title, err)
			}
			res.Findings++
		}
	}
	if s.log != nil {
		_ = s.log.Append(ctx, audit.Entry{Actor: "discovery", Action: "discovery.run", Resource: j.ID, Result: audit.ResultAllow})
	}
	return res, nil
}

func (s *Service) project(ctx context.Context, entityID string, a inventory.Asset, o connector.Observation) error {
	if s.graph == nil {
		return nil
	}
	now := a.LastSeen
	if now.IsZero() {
		now = s.now().UTC()
	}
	kind, props := graphOf(a)
	if kind == "" {
		return nil
	}
	e := graph.Entity{
		Tenant: entityID, Kind: kind, Props: props,
		FirstSeen: a.FirstSeen, LastSeen: now, InScope: true,
		Sources: []string{o.SourceID},
	}
	e, _, err := s.graph.UpsertEntity(ctx, e)
	if err != nil {
		return err
	}
	org, _, err := s.graph.UpsertEntity(ctx, graph.Entity{
		Tenant: entityID, Kind: graph.KindOrganization,
		Props:     map[string]string{"name": entityID},
		FirstSeen: a.FirstSeen, LastSeen: now, InScope: true,
		Sources: []string{"discovery"},
	})
	if err != nil {
		return err
	}
	if err := s.graph.UpsertRelation(ctx, graph.Relation{
		Tenant: entityID, Type: graph.RelOwns,
		FromFP: org.Fingerprint, ToFP: e.Fingerprint,
		Props: map[string]string{"source": o.SourceID}, EvidenceRef: o.RawRef, TS: now,
	}); err != nil {
		return err
	}
	if o.Kind == "ip" {
		if from := strings.TrimSpace(o.Payload["resolves_from"]); from != "" {
			if err := s.linkDomain(ctx, entityID, from, e, o, now); err != nil {
				return err
			}
		}
	}
	if o.Kind == "domain" {
		if from := strings.TrimSpace(o.Payload["cname_of"]); from != "" {
			if err := s.linkDomain(ctx, entityID, from, e, o, now); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) linkDomain(ctx context.Context, entityID, domain string, target graph.Entity, o connector.Observation, now time.Time) error {
	src, _, err := s.graph.UpsertEntity(ctx, graph.Entity{
		Tenant: entityID, Kind: graph.KindDomain,
		Props:     map[string]string{"value": graph.NormalizeDomain(domain)},
		FirstSeen: now, LastSeen: now, InScope: true, Sources: []string{o.SourceID},
	})
	if err != nil {
		return err
	}
	return s.graph.UpsertRelation(ctx, graph.Relation{
		Tenant: entityID, Type: graph.RelResolvesTo,
		FromFP: src.Fingerprint, ToFP: target.Fingerprint,
		Props: map[string]string{"source": o.SourceID}, EvidenceRef: o.RawRef, TS: now,
	})
}

func graphOf(a inventory.Asset) (string, map[string]string) {
	switch a.Kind {
	case "domain":
		return graph.KindDomain, map[string]string{"value": a.DisplayName}
	case "ip":
		return graph.KindIPBlock, map[string]string{"cidr": a.DisplayName}
	case "url":
		return graph.KindWebApp, map[string]string{"url": a.DisplayName}
	case "repo":
		return graph.KindCodeRepo, map[string]string{"url": a.DisplayName}
	case "org":
		return graph.KindOrganization, map[string]string{"name": a.DisplayName}
	default:
		return "", nil
	}
}

func toStrings(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
