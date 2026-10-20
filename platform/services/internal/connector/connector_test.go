package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSeedInfersKinds(t *testing.T) {
	obs, err := Seed{}.Run(context.Background(), Input{Seeds: []string{
		"Example.com", "192.0.2.10", "https://app.example.com/x",
		"https://github.com/acme/repo", "Example.com",
	}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, o := range obs {
		got[o.Value] = o.Kind
	}
	if got["Example.com"] != "domain" || got["192.0.2.10"] != "ip" ||
		got["https://app.example.com/x"] != "url" || got["https://github.com/acme/repo"] != "repo" {
		t.Fatalf("kind 推断不符: %+v", got)
	}
	if len(obs) != 4 {
		t.Fatalf("去重后应为 4，实际 %d", len(obs))
	}
}

func TestCTParsesAndDedupes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name_value":"a.example.com\n*.b.example.com\na.example.com","common_name":"a.example.com","issuer_name":"Test CA","not_before":"2026-01-01"}]`))
	}))
	defer srv.Close()
	c := NewCT().WithBaseURL(srv.URL)
	obs, err := c.Run(context.Background(), Input{Seeds: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 2 {
		t.Fatalf("应去重为 2，实际 %d: %+v", len(obs), obs)
	}
	if obs[0].Value != "a.example.com" || obs[0].SourceID != "ct" {
		t.Fatalf("观察不符: %+v", obs[0])
	}
}

func TestCTHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := NewCT().WithBaseURL(srv.URL).Run(context.Background(), Input{Seeds: []string{"example.com"}}); err == nil {
		t.Fatal("HTTP 500 应上浮")
	}
}
