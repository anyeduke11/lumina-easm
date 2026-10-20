// Package config 集中装载与校验服务端配置（WP-M0-02/NFR-MNT-001）。
//
// 设计口径：env 只在 Load 读取一次；非法/半设配置在启动期 fail loud，
// 不把错误拖到运行期。密钥字段只从 env 读，不落日志（Redacted 仅输出是否设置）。
package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAIModel   = "sensenova-6.8-flash-lite"
	defaultAIBaseURL = "https://token.sensenova.cn/v1"
)

// Config 服务端配置快照。零值字段表示未设置/使用默认值。
type Config struct {
	Port string
	Env  string

	SingleUser bool
	DevTokens  string

	PGDSN        string
	TemporalHost string

	EvidenceMode  string
	EvidenceDir   string
	MinioEndpoint string
	MinioBucket   string
	MinioAK       string
	MinioSK       string
	MinioSSL      bool

	SandboxURL      string
	VerifyCmd       string
	VerifyTimeout   time.Duration
	VerifyWorkspace string
	VerifyFSizeMB   int
	VerifyNice      int

	AIBaseURL string
	AIModel   string
	AIAPIKey  string

	EvalThresholds     string
	ScoreWeights       string
	ScoreThresholds    string
	SecretProbe        bool
	SecretProbePrivate bool

	AssetStaleAfter  time.Duration
	AssetRetireAfter time.Duration

	AlertWebhook  string
	AlertMailTo   string
	AlertMailFrom string
	SOARWebhook   string
	SOARSecret    string
	ASMURL        string
	ASMToken      string
	CloudURL      string
	CloudToken    string

	ConsoleDir          string
	RequireConfirmation bool

	OIDCIssuer       string
	OIDCAudience     string
	OIDCJWKSURL      string
	BreakGlassHash   string
	PasskeyPublicKey string
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) (int, error) {
	raw := os.Getenv(k)
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s 非法: %q（须为非负整数）", k, raw)
	}
	return n, nil
}

func envBool(k string) bool { return os.Getenv(k) == "1" }

// envBoolDefaultTrue：未设=开启；显式 0/false/off/no 才关闭（高危闸默认开，降级须明示）。
func envBoolDefaultTrue(k string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(k))) {
	case "0", "false", "off", "no":
		return false
	}
	return true
}

// Load 读取 env 并校验；任何非法/半设配置返回 error，由 main fail loud。
func Load() (Config, error) {
	to, err := time.ParseDuration(env("EASM_VERIFY_TIMEOUT", "10m"))
	if err != nil {
		return Config{}, fmt.Errorf("EASM_VERIFY_TIMEOUT 非法: %w", err)
	}
	staleAfter, err := time.ParseDuration(env("EASM_ASSET_STALE_AFTER", "720h"))
	if err != nil {
		return Config{}, fmt.Errorf("EASM_ASSET_STALE_AFTER 非法: %w", err)
	}
	retireAfter, err := time.ParseDuration(env("EASM_ASSET_RETIRE_AFTER", "2160h"))
	if err != nil {
		return Config{}, fmt.Errorf("EASM_ASSET_RETIRE_AFTER 非法: %w", err)
	}
	fsize, err := envInt("EASM_VERIFY_FSIZE_MB", 64)
	if err != nil {
		return Config{}, err
	}
	nice, err := envInt("EASM_VERIFY_NICE", 19)
	if err != nil {
		return Config{}, err
	}
	c := Config{
		Port: env("PORT", "8087"),
		Env:  os.Getenv("EASM_ENV"),

		SingleUser: envBool("EASM_SINGLE_USER"),
		DevTokens:  os.Getenv("EASM_DEV_TOKENS"),

		PGDSN:        os.Getenv("EASM_PG_DSN"),
		TemporalHost: os.Getenv("EASM_TEMPORAL_HOST"),

		EvidenceMode:  env("EASM_EVIDENCE", "file"),
		EvidenceDir:   env("EASM_EVIDENCE_DIR", "evidence-store"),
		MinioEndpoint: env("EASM_MINIO_ENDPOINT", "127.0.0.1:9000"),
		MinioBucket:   env("EASM_MINIO_BUCKET", "easm-evidence"),
		MinioAK:       os.Getenv("EASM_MINIO_AK"),
		MinioSK:       os.Getenv("EASM_MINIO_SK"),
		MinioSSL:      env("EASM_MINIO_SSL", "false") == "true",

		SandboxURL:      os.Getenv("EASM_SANDBOX_URL"),
		VerifyCmd:       os.Getenv("EASM_VERIFY_CMD"),
		VerifyTimeout:   to,
		VerifyWorkspace: env("EASM_VERIFY_WORKSPACE", "/tmp/easm-verify"),
		VerifyFSizeMB:   fsize,
		VerifyNice:      nice,

		AIBaseURL: env("EASM_AI_BASE_URL", defaultAIBaseURL),
		AIModel:   env("EASM_AI_MODEL", defaultAIModel),
		AIAPIKey:  os.Getenv("EASM_AI_API_KEY"),

		EvalThresholds:     os.Getenv("EASM_EVAL_THRESHOLDS"),
		ScoreWeights:       os.Getenv("EASM_SCORE_WEIGHTS"),
		ScoreThresholds:    os.Getenv("EASM_SCORE_THRESHOLDS"),
		SecretProbe:        envBool("EASM_SECRET_PROBE"),
		SecretProbePrivate: envBool("EASM_SECRET_PROBE_ALLOW_PRIVATE"),
		AssetStaleAfter:    staleAfter,
		AssetRetireAfter:   retireAfter,

		AlertWebhook:  os.Getenv("EASM_ALERT_WEBHOOK"),
		AlertMailTo:   os.Getenv("EASM_ALERT_MAIL_TO"),
		AlertMailFrom: env("EASM_ALERT_MAIL_FROM", "easm@localhost"),
		SOARWebhook:   os.Getenv("EASM_SOAR_WEBHOOK"),
		SOARSecret:    os.Getenv("EASM_SOAR_SECRET"),
		ASMURL:        os.Getenv("EASM_ASM_URL"),
		ASMToken:      os.Getenv("EASM_ASM_TOKEN"),
		CloudURL:      os.Getenv("EASM_CLOUD_URL"),
		CloudToken:    os.Getenv("EASM_CLOUD_TOKEN"),

		ConsoleDir: env("EASM_CONSOLE_DIR", "console"),
		// 默认开启（AX-5：高危动作确认不可默认旁路）；EASM_REQUIRE_CONFIRMATION=0 显式关闭。
		RequireConfirmation: envBoolDefaultTrue("EASM_REQUIRE_CONFIRMATION"),

		OIDCIssuer:       os.Getenv("EASM_OIDC_ISSUER"),
		OIDCAudience:     os.Getenv("EASM_OIDC_AUDIENCE"),
		OIDCJWKSURL:      os.Getenv("EASM_OIDC_JWKS_URL"),
		BreakGlassHash:   os.Getenv("EASM_BREAKGLASS_HASH"),
		PasskeyPublicKey: os.Getenv("EASM_PASSKEY_PUBLIC_KEY"),
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate 启动期校验：拒绝非法枚举、半设 AI/SOAR/OIDC、生产 dev 令牌。
func (c Config) Validate() error {
	if n, err := strconv.Atoi(c.Port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("PORT 非法: %q", c.Port)
	}
	switch c.EvidenceMode {
	case "file", "minio":
	default:
		return fmt.Errorf("EASM_EVIDENCE 非法取值 %q（须 file|minio）", c.EvidenceMode)
	}
	if c.VerifyTimeout <= 0 {
		return fmt.Errorf("EASM_VERIFY_TIMEOUT 必须为正时长")
	}
	aiSet := c.AIAPIKey != "" || os.Getenv("EASM_AI_BASE_URL") != "" || os.Getenv("EASM_AI_MODEL") != ""
	if aiSet && strings.TrimSpace(c.AIAPIKey) == "" {
		return fmt.Errorf("EASM_AI_API_KEY 缺失（EASM_AI_* 三件套须同设）")
	}
	if (c.SOARWebhook == "") != (c.SOARSecret == "") {
		return fmt.Errorf("EASM_SOAR_WEBHOOK 与 EASM_SOAR_SECRET 必须同设")
	}
	if c.AssetStaleAfter <= 0 || c.AssetRetireAfter <= 0 || c.AssetRetireAfter <= c.AssetStaleAfter {
		return fmt.Errorf("资产衰减需 0 < EASM_ASSET_STALE_AFTER < EASM_ASSET_RETIRE_AFTER")
	}
	if c.ASMURL != "" {
		u, err := url.Parse(c.ASMURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("EASM_ASM_URL 须为 http(s) URL")
		}
	}
	if c.SecretProbePrivate && !c.SecretProbe {
		return fmt.Errorf("EASM_SECRET_PROBE_ALLOW_PRIVATE 仅在 EASM_SECRET_PROBE=1 时生效（拒绝静默无效的安全降级配置）")
	}
	if c.CloudURL != "" {
		u, err := url.Parse(c.CloudURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("EASM_CLOUD_URL 须为 http(s) URL")
		}
	}
	if c.OIDCIssuer != "" {
		if c.OIDCAudience == "" || c.OIDCJWKSURL == "" {
			return fmt.Errorf("EASM_OIDC_ISSUER 设置时 EASM_OIDC_AUDIENCE / EASM_OIDC_JWKS_URL 必须同设")
		}
	}
	if c.BreakGlassHash != "" {
		if len(c.BreakGlassHash) != 64 {
			return fmt.Errorf("EASM_BREAKGLASS_HASH 须为 64 位 hex（SHA-256）")
		}
		for _, r := range c.BreakGlassHash {
			if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
				return fmt.Errorf("EASM_BREAKGLASS_HASH 须为 hex")
			}
		}
	}
	if c.Env == "production" {
		if c.DevTokens != "" {
			return fmt.Errorf("EASM_ENV=production 禁用 dev 静态令牌（EASM_DEV_TOKENS）")
		}
		if c.OIDCIssuer == "" {
			return fmt.Errorf("EASM_ENV=production 必须配置 OIDC（EASM_OIDC_ISSUER/AUDIENCE/JWKS_URL）")
		}
	}
	return nil
}

// Redacted 启动日志摘要：只标注是否设置，不输出密钥/DSN 明文。
func (c Config) Redacted() string {
	mark := func(v string) string {
		if v == "" {
			return "unset"
		}
		return "set"
	}
	return fmt.Sprintf("port=%s env=%q single_user=%v backend=%s evidence=%s ai=%s oidc=%s breakglass=%s passkey=%s asm=%s cloud=%s confirm=%v",
		c.Port, c.Env, c.SingleUser,
		map[bool]string{true: "postgres", false: "memory"}[c.PGDSN != ""],
		c.EvidenceMode, mark(c.AIAPIKey), mark(c.OIDCIssuer), mark(c.BreakGlassHash), mark(c.PasskeyPublicKey), mark(c.ASMURL), mark(c.CloudURL), c.RequireConfirmation)
}
