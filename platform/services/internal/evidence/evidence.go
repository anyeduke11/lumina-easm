// Package evidence 实现证据对象存储接缝（设计方案 `dsh-storage-evidence` / ENH-05）。
// 契约（C-5 证据口径唯一）：任一结论的原始产物落此固化，Put 返回可回溯 ref，
// Get 按 ref 取回不可变字节；同 key 二次写入一律拒绝（WORM append-once=防篡改）。
// MVP 过渡形态=本地文件（FileStore）；批十装载 Provider=MinIO/S3（MinIOStore）——
// 接缝不变、上层零改动（设计方案 §4.2 Provider 替换）。
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

var (
	ErrEmpty     = errors.New("evidence: 空数据不可固化")
	ErrImmutable = errors.New("evidence: 对象已存在，禁止覆盖（WORM）")
	ErrNotFound  = errors.New("evidence: ref 无法回溯到对象")
	ErrBadKey    = errors.New("evidence: 非法 key（禁空/绝对路径/目录穿越）")
	ErrBadRef    = errors.New("evidence: ref 与本存储后端不匹配")
)

// Store 证据固化端口（FileStore/MinIOStore 同契约 C-6，SDK 类型不外泄 AX-6）。
type Store interface {
	// Put 固化一份不可变原始产物到 key（如 tenant/contentHash.bin），返回带后端方案的 ref。
	// 同 key 已存在 → ErrImmutable（WORM）。
	Put(ctx context.Context, key string, data []byte) (ref string, err error)
	// Get 按 Put 返回的 ref 回溯原始字节；不存在 → ErrNotFound。
	Get(ctx context.Context, ref string) ([]byte, error)
	// RefOf 逻辑 key → 规范 ref（幂等重放场景：Put 返回 ErrImmutable 时取既有 ref，
	// 内容同哈希=同 key，无需读回）。
	RefOf(key string) string
	// Kind 后端标识（"file"|"minio"），供能力边界声明/徽标。
	Kind() string
}

// Hash 内容 sha256（十六进制）：证据 key 的稳定成分，同内容可去重、异内容必异 key。
func Hash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// RefInTenant C-5 越权防线的唯一口径：ref 的路径段序列须含 /<tenant>/
// （兼容采集/暗网层 `ext-scan/<tenant>/`、`darkweb/<tenant>/` 等带前缀布局）。
// 全作用域主体（admin）同样受本闸约束=防传错 ref 串租户；导出/回溯面共用此判定，
// 避免两处规则漂移。
func RefInTenant(ref, tenant string) bool {
	if ref == "" || tenant == "" {
		return false
	}
	trimmed := strings.TrimPrefix(strings.TrimPrefix(ref, "file://"), "minio://")
	return strings.Contains("/"+trimmed+"/", "/"+tenant+"/")
}

// ValidKey 校验逻辑 key：非空、不含反斜杠、每段非空且非 "."/".."（挡绝对路径与穿越）。
// 后端无关的入口守卫，两种 Provider 共用（口径唯一）。
func ValidKey(key string) bool {
	if key == "" || strings.Contains(key, "\\") {
		return false
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
