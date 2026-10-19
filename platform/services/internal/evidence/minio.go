// minio.go — ENH-05 装载形态：证据落 MinIO/S3 对象存储。
// 与 FileStore 同契约（C-6）；WORM=Put 前 StatObject 命中即拒覆盖（应用层不可变闸）。
// 口径边界：真正合规锁（Object Lock/Retention、桶版本化）在部署层或取证正式化（G8-02）启用；
// 本批以「不可变 key + 覆盖拒绝 + 内容哈希」保证 C-5 回溯不被静默篡改（fail loud）。
package evidence

import (
	"bytes"
	"context"
	"errors"
	"io"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type MinIOStore struct {
	cli    *minio.Client
	bucket string
	prefix string // minio://<bucket>/
}

// NewMinIOStore 建 MinIO 客户端并确保桶存在（不存在则创建）。endpoint 形如 127.0.0.1:9000。
func NewMinIOStore(endpoint, accessKey, secretKey, bucket string, useSSL bool) (*MinIOStore, error) {
	if bucket == "" {
		return nil, errors.New("evidence: bucket 必填")
	}
	cli, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	found, err := cli.BucketExists(ctx, bucket)
	if err != nil {
		return nil, err
	}
	if !found {
		if err := cli.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: "us-east-1"}); err != nil {
			return nil, err
		}
	}
	return &MinIOStore{cli: cli, bucket: bucket, prefix: "minio://" + bucket + "/"}, nil
}

func (m *MinIOStore) Kind() string { return "minio" }

// RefOf key → minio://bucket/key 规范 ref（与 Put 成功返回同形态）。
func (m *MinIOStore) RefOf(key string) string { return m.prefix + key }

func (m *MinIOStore) Put(ctx context.Context, key string, data []byte) (string, error) {
	if len(data) == 0 {
		return "", ErrEmpty
	}
	if !ValidKey(key) {
		return "", ErrBadKey
	}
	// WORM 闸：已存在=覆盖=篡改，一律拒绝（非静默替换）
	if _, err := m.cli.StatObject(ctx, m.bucket, key, minio.StatObjectOptions{}); err == nil {
		return "", ErrImmutable
	} else if !isNotFound(err) {
		return "", err
	}
	info, err := m.cli.PutObject(ctx, m.bucket, key, bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: "application/octet-stream",
			UserMetadata: map[string]string{"sha256": Hash(data)}})
	if err != nil {
		return "", err
	}
	_ = info
	return m.prefix + key, nil
}

func (m *MinIOStore) Get(ctx context.Context, ref string) ([]byte, error) {
	if len(ref) < len(m.prefix) || ref[:len(m.prefix)] != m.prefix {
		return nil, ErrBadRef
	}
	key := ref[len(m.prefix):]
	if !ValidKey(key) {
		return nil, ErrBadRef
	}
	obj, err := m.cli.GetObject(ctx, m.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		if isNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer obj.Close()
	b, err := io.ReadAll(obj)
	if err != nil {
		if isNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return b, nil
}

// isNotFound 区分「对象不存在」（404/NoSuchKey/NoSuchBucket）与真实故障（后者须上浮，不静默）。
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	e := minio.ToErrorResponse(err)
	return e.StatusCode == 404 || e.Code == "NoSuchKey" || e.Code == "NoSuchBucket"
}
