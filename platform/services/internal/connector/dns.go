package connector

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// Resolver DNS 解析接缝（测试可替换；生产用 net.DefaultResolver）。
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

type netResolver struct{ r *net.Resolver }

func (n netResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return n.r.LookupHost(ctx, host)
}
func (n netResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	return n.r.LookupCNAME(ctx, host)
}

// DNS 发现 A/AAAA 与 CNAME；输出 domain/ip 观察并携带解析关系。
type DNS struct{ res Resolver }

func NewDNS() *DNS { return &DNS{res: netResolver{r: net.DefaultResolver}} }

func (d *DNS) WithResolver(r Resolver) *DNS {
	if r != nil {
		d.res = r
	}
	return d
}

func (d *DNS) Name() string { return "dns" }

func (d *DNS) Run(ctx context.Context, in Input) ([]Observation, error) {
	if d.res == nil {
		d.res = netResolver{r: net.DefaultResolver}
	}
	now := time.Now().UTC()
	var out []Observation
	for _, raw := range in.Seeds {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if host == "" || net.ParseIP(host) != nil || strings.Contains(host, "/") {
			continue
		}
		out = append(out, Observation{Kind: "domain", Value: host, SourceID: "dns", ObservedAt: now})
		if cname, err := d.res.LookupCNAME(ctx, host); err == nil {
			cname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cname), "."))
			if cname != "" && cname != host {
				out = append(out, Observation{
					Kind: "domain", Value: cname, SourceID: "dns",
					Payload: map[string]string{"cname_of": host}, ObservedAt: now,
				})
			}
		} else if !isNotFound(err) {
			return nil, err
		}
		ips, err := d.res.LookupHost(ctx, host)
		if err != nil {
			if isNotFound(err) {
				continue
			}
			return nil, err
		}
		for _, ip := range ips {
			out = append(out, Observation{
				Kind: "ip", Value: ip, SourceID: "dns",
				Payload: map[string]string{"resolves_from": host}, ObservedAt: now,
			})
		}
	}
	return out, nil
}

func isNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}
