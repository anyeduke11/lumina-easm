package config

import (
	"strings"
	"testing"
)

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"PORT", "EASM_ENV", "EASM_SINGLE_USER", "EASM_DEV_TOKENS", "EASM_PG_DSN",
		"EASM_TEMPORAL_HOST", "EASM_EVIDENCE", "EASM_EVIDENCE_DIR", "EASM_MINIO_ENDPOINT",
		"EASM_MINIO_BUCKET", "EASM_MINIO_AK", "EASM_MINIO_SK", "EASM_MINIO_SSL",
		"EASM_SANDBOX_URL", "EASM_VERIFY_CMD", "EASM_VERIFY_TIMEOUT", "EASM_VERIFY_WORKSPACE",
		"EASM_VERIFY_FSIZE_MB", "EASM_VERIFY_NICE", "EASM_AI_BASE_URL", "EASM_AI_MODEL",
		"EASM_AI_API_KEY", "EASM_EVAL_THRESHOLDS", "EASM_SCORE_WEIGHTS", "EASM_SCORE_THRESHOLDS",
		"EASM_SECRET_PROBE", "EASM_SECRET_PROBE_ALLOW_PRIVATE", "EASM_ALERT_WEBHOOK", "EASM_ALERT_MAIL_TO", "EASM_ALERT_MAIL_FROM",
		"EASM_SOAR_WEBHOOK", "EASM_SOAR_SECRET", "EASM_ASM_URL", "EASM_ASM_TOKEN", "EASM_CLOUD_URL", "EASM_CLOUD_TOKEN", "EASM_CONSOLE_DIR", "EASM_REQUIRE_CONFIRMATION",
		"EASM_OIDC_ISSUER", "EASM_OIDC_AUDIENCE", "EASM_OIDC_JWKS_URL", "EASM_BREAKGLASS_HASH", "EASM_PASSKEY_PUBLIC_KEY",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Port != "8087" || c.EvidenceMode != "file" || c.VerifyTimeout.String() != "10m0s" {
		t.Fatalf("默认值不符: %+v", c)
	}
	if !c.RequireConfirmation {
		t.Fatal("高危动作确认应默认开启（AX-5；显式 =0 才关闭）")
	}
	t.Setenv("EASM_REQUIRE_CONFIRMATION", "0")
	c, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.RequireConfirmation {
		t.Fatal("EASM_REQUIRE_CONFIRMATION=0 应显式关闭")
	}
}

func TestLoadRejectsHalfAI(t *testing.T) {
	clearEnv(t)
	t.Setenv("EASM_AI_BASE_URL", "https://example.invalid/v1")
	if _, err := Load(); err == nil {
		t.Fatal("AI 半设应拒绝")
	}
}

func TestLoadRejectsInvalidEvidence(t *testing.T) {
	clearEnv(t)
	t.Setenv("EASM_EVIDENCE", "s3")
	if _, err := Load(); err == nil {
		t.Fatal("非法 evidence 应拒绝")
	}
}

func TestASMURLValidated(t *testing.T) {
	clearEnv(t)
	t.Setenv("EASM_ASM_URL", "not-a-url")
	if _, err := Load(); err == nil {
		t.Fatal("非法 ASM URL 应拒绝")
	}
	t.Setenv("EASM_ASM_URL", "https://asm.example/api")
	if _, err := Load(); err != nil {
		t.Fatalf("合法 ASM URL 应通过: %v", err)
	}
}

func TestBreakGlassHashValidated(t *testing.T) {
	clearEnv(t)
	t.Setenv("EASM_BREAKGLASS_HASH", "bad")
	if _, err := Load(); err == nil {
		t.Fatal("非法 break-glass hash 应拒绝")
	}
	t.Setenv("EASM_BREAKGLASS_HASH", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if _, err := Load(); err != nil {
		t.Fatalf("合法 hash 应通过: %v", err)
	}
}

func TestProductionRequiresOIDCAndRejectsDevTokens(t *testing.T) {
	clearEnv(t)
	t.Setenv("EASM_ENV", "production")
	t.Setenv("EASM_DEV_TOKENS", "tok:R7:*")
	if _, err := Load(); err == nil {
		t.Fatal("生产 + dev 令牌应拒绝")
	}
	t.Setenv("EASM_DEV_TOKENS", "")
	t.Setenv("EASM_OIDC_ISSUER", "https://idp.example")
	if _, err := Load(); err == nil {
		t.Fatal("OIDC 半设应拒绝")
	}
	t.Setenv("EASM_OIDC_AUDIENCE", "easm")
	t.Setenv("EASM_OIDC_JWKS_URL", "https://idp.example/jwks")
	if _, err := Load(); err != nil {
		t.Fatalf("完整 OIDC 应通过: %v", err)
	}
}

func TestSecretProbePrivateOptInRequiresProbe(t *testing.T) {
	clearEnv(t)
	t.Setenv("EASM_SECRET_PROBE_ALLOW_PRIVATE", "1")
	if _, err := Load(); err == nil {
		t.Fatal("仅开私网放行而不开探针应拒绝（避免静默无效的安全降级配置）")
	}
	t.Setenv("EASM_SECRET_PROBE", "1")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !c.SecretProbe || !c.SecretProbePrivate {
		t.Fatalf("显式开启后应生效: %+v", c)
	}
}

func TestRedactedDoesNotLeakSecrets(t *testing.T) {
	clearEnv(t)
	t.Setenv("EASM_AI_API_KEY", "sk-super-secret")
	t.Setenv("EASM_PG_DSN", "postgres://user:pass@host/db")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	out := c.Redacted()
	if strings.Contains(out, "sk-super-secret") || strings.Contains(out, "pass@host") {
		t.Fatalf("Redacted 泄露密钥: %s", out)
	}
}
