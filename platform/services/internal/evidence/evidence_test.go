package evidence

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nonce 生成一次性随机后缀，保证跨运行 key 唯一（MinIO 桶持久）。
func nonce() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// 为什么（C-5/C-6）：两种 Provider 必须过同一契约——round-trip 字节一致、
// WORM 拒覆盖、空/穿越 key 拒绝、ref 后端匹配、未知 ref=NotFound。
// FileStore 恒跑；MinIOStore 仅在配置 EASM_MINIO_ENDPOINT 时跑（同 pgstore 集成门控范式）。

func runContract(t *testing.T, s Store, wantKind string) {
	t.Helper()
	ctx := context.Background()
	if s.Kind() != wantKind {
		t.Fatalf("Kind=%q 应 %q", s.Kind(), wantKind)
	}
	// nonce 使每次运行的 key 唯一：FileStore 有 t.TempDir 隔离，MinIO 桶跨运行持久，
	// 固定 key 会在二次运行命中旧对象→误判 WORM。唯一 key 保证可重复运行。
	data := []byte("evidence-payload-\x00bin\xff" + wantKind + "-" + nonce())
	key := "t-a/" + Hash(data) + ".bin"

	ref, err := s.Put(ctx, key, data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("回溯字节不一致: got %d want %d", len(got), len(data))
	}

	// WORM：同 key 二次写=覆盖=篡改，必须拒绝
	if _, err := s.Put(ctx, key, data); !errors.Is(err, ErrImmutable) {
		t.Errorf("同 key 重写应 ErrImmutable，实际 %v", err)
	}
	// 空数据不可固化
	if _, err := s.Put(ctx, "t-a/empty.bin", nil); !errors.Is(err, ErrEmpty) {
		t.Errorf("空数据应 ErrEmpty，实际 %v", err)
	}
	// 目录穿越 key 拒绝
	if _, err := s.Put(ctx, "../escape.bin", data); !errors.Is(err, ErrBadKey) {
		t.Errorf("穿越 key 应 ErrBadKey，实际 %v", err)
	}
	// 未知 ref（同格式、同后端、仅 key 不存在）：NotFound（非静默空返回——fail loud）
	if !strings.HasSuffix(ref, ".bin") {
		t.Fatalf("契约假设 ref 以 .bin 结尾，实际 %q", ref)
	}
	missing := ref[:len(ref)-len(".bin")] + "-nope.bin"
	if _, err := s.Get(ctx, missing); !errors.Is(err, ErrNotFound) {
		t.Errorf("未知 ref 应 ErrNotFound，实际 %v", err)
	}
}

func TestFileStoreContract(t *testing.T) {
	fs, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runContract(t, fs, "file")
}

// Get 伪造越界 ref 不得读出 store 根之外（沙箱逃逸防线）。
func TestFileStoreRejectsEscapeRef(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 在根之外放一个敏感文件，伪造 file:// ref 指过去
	outside := filepath.Join(filepath.Dir(dir), "easm-batch10-secret.txt")
	defer os.Remove(outside)
	if err := os.WriteFile(outside, []byte("TOP-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Get(context.Background(), "file://"+outside); err == nil {
		t.Error("越界 ref 应被拒（读了沙箱外文件=逃逸）")
	}
}

func TestValidKey(t *testing.T) {
	for _, bad := range []string{"", "/abs", "a/../b", "a//b", "..", `a\b`} {
		if ValidKey(bad) {
			t.Errorf("应非法: %q", bad)
		}
	}
	for _, ok := range []string{"t-a/h.bin", "a/b/c.bin", "x"} {
		if !ValidKey(ok) {
			t.Errorf("应合法: %q", ok)
		}
	}
}

func TestMinIOStoreContract(t *testing.T) {
	ep := os.Getenv("EASM_MINIO_ENDPOINT")
	if ep == "" {
		t.Skip("未配置 EASM_MINIO_ENDPOINT，跳过 MinIO 契约（本机非容器 minio server 就绪后启用）")
	}
	st, err := NewMinIOStore(ep, os.Getenv("EASM_MINIO_AK"), os.Getenv("EASM_MINIO_SK"),
		os.Getenv("EASM_MINIO_BUCKET"), false)
	if err != nil {
		t.Fatalf("NewMinIOStore: %v", err)
	}
	runContract(t, st, "minio")
}
