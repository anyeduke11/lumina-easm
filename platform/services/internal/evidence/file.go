// file.go — MVP 过渡形态证据存储（本地文件，WORM=O_EXCL 仅追加一次）。
// ref 形态：file://<绝对路径>；Get 拒绝越出 store 根目录的伪造 ref（回溯不可逃逸沙箱）。
package evidence

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type FileStore struct{ root string }

// NewFileStore 建本地证据根目录（不存在则创建）。
func NewFileStore(root string) (*FileStore, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o750); err != nil {
		return nil, err
	}
	return &FileStore{root: abs}, nil
}

func (f *FileStore) Kind() string { return "file" }

// RefOf key → file:// 规范路径（与 Put 成功返回同形态）。
func (f *FileStore) RefOf(key string) string {
	return "file://" + filepath.Join(f.root, filepath.FromSlash(key))
}

func (f *FileStore) Put(_ context.Context, key string, data []byte) (string, error) {
	if len(data) == 0 {
		return "", ErrEmpty
	}
	if !ValidKey(key) {
		return "", ErrBadKey
	}
	p := filepath.Join(f.root, filepath.FromSlash(key))
	if !underRoot(f.root, p) {
		return "", ErrBadKey
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return "", err
	}
	// O_EXCL：已存在即失败=WORM 仅追加一次（覆盖=篡改，一律拒绝）
	fp, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return "", ErrImmutable
		}
		return "", err
	}
	defer fp.Close()
	if _, err := fp.Write(data); err != nil {
		return "", err
	}
	return "file://" + p, nil
}

func (f *FileStore) Get(_ context.Context, ref string) ([]byte, error) {
	if !strings.HasPrefix(ref, "file://") {
		return nil, ErrBadRef
	}
	p := filepath.Clean(strings.TrimPrefix(ref, "file://"))
	if !underRoot(f.root, p) {
		return nil, ErrBadRef // 伪造 ref 不得读出沙箱外文件
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return b, nil
}

// underRoot 判定 p 规范化后仍在 root 之内（防 .. 逃逸与绝对路径注入）。
func underRoot(root, p string) bool {
	rp, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rp != ".." && !strings.HasPrefix(rp, ".."+string(filepath.Separator)) && !filepath.IsAbs(rp)
}
