package connector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestASMPostsSeedsAndParsesObservations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method=%s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("auth=%s", r.Header.Get("Authorization"))
		}
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		if len(in["seeds"].([]any)) != 1 {
			t.Errorf("seeds=%v", in["seeds"])
		}
		_, _ = w.Write([]byte(`{"observations":[{"kind":"domain","value":"asm.example"},{"kind":"","value":"skip"}]}`))
	}))
	defer srv.Close()
	a, err := NewASM(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	obs, err := a.Run(context.Background(), Input{EntityID: "t-a", Seeds: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].Value != "asm.example" || obs[0].SourceID != "asm" {
		t.Fatalf("observations=%+v", obs)
	}
}

func TestCloudName(t *testing.T) {
	c, err := NewCloud("https://cloud.example/api", "tok")
	if err != nil {
		t.Fatal(err)
	}
	if c.Name() != "cloud" {
		t.Fatalf("name=%s", c.Name())
	}
}

func TestASMRejectsBadURL(t *testing.T) {
	if _, err := NewASM("not-a-url", ""); err == nil {
		t.Fatal("非法 URL 应拒绝")
	}
}
