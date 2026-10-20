package httpapi

import (
	"net/http"
	"testing"

	"github.com/wangdev88/easm-platform/platform/services/internal/audit"
	"github.com/wangdev88/easm-platform/platform/services/internal/authn"
)

func TestBreakGlassBearerAuthenticates(t *testing.T) {
	token, hash, err := authn.GenerateBreakGlass()
	if err != nil {
		t.Fatal(err)
	}
	bg, err := authn.NewBreakGlass(hash, &audit.MemLog{})
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := newConfirmTestServer(t, false, WithBreakGlass(bg))
	resp, body := get(srv, "/v1/entities", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("break-glass 应可认证，实际 %d body=%v", resp.StatusCode, body)
	}
}
