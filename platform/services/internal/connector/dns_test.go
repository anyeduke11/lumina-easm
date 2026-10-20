package connector

import (
	"context"
	"testing"
)

type fakeResolver struct {
	hosts map[string][]string
	cname map[string]string
}

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	return f.hosts[host], nil
}
func (f fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	return f.cname[host], nil
}

func TestDNSConnectorEmitsHostsAndCNAME(t *testing.T) {
	d := NewDNS().WithResolver(fakeResolver{
		hosts: map[string][]string{"example.com": {"192.0.2.10", "2001:db8::1"}},
		cname: map[string]string{"example.com": "edge.example.net."},
	})
	obs, err := d.Run(context.Background(), Input{Seeds: []string{"Example.com."}})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 4 { // domain + cname + 2 ip
		t.Fatalf("观察数不符: %d %+v", len(obs), obs)
	}
	byKind := map[string]int{}
	for _, o := range obs {
		byKind[o.Kind]++
	}
	if byKind["domain"] != 2 || byKind["ip"] != 2 {
		t.Fatalf("kind 分布不符: %+v", byKind)
	}
}
