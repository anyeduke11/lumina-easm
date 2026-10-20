// Package main 生成/使用 passkey（ES256 challenge-response，FR-TEN-005/NFR-SEC-002/AX-5）。
//
// 用法：
//
//	go run ./platform/services/cmd/passkey -init -out passkey-private.pem
//	go run ./platform/services/cmd/passkey -sign -key passkey-private.pem -challenge <challenge>
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/wangdev88/easm-platform/platform/services/internal/authn"
)

func main() {
	initFlag := flag.Bool("init", false, "生成 P-256 密钥对")
	signFlag := flag.Bool("sign", false, "对 challenge 签名")
	out := flag.String("out", "passkey-private.pem", "私钥输出路径（0600）")
	keyPath := flag.String("key", "passkey-private.pem", "私钥路径")
	challenge := flag.String("challenge", "", "服务端 challenge")
	flag.Parse()

	switch {
	case *initFlag:
		priv, pub, err := authn.GeneratePasskey()
		if err != nil {
			fmt.Fprintln(os.Stderr, "generate:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*out, []byte(priv), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "write:", err)
			os.Exit(1)
		}
		fmt.Printf("EASM_PASSKEY_PUBLIC_KEY=%s\n", pub)
		fmt.Printf("private key: %s（离线保管，勿入库）\n", *out)
	case *signFlag:
		if *challenge == "" {
			fmt.Fprintln(os.Stderr, "-challenge 必填")
			os.Exit(2)
		}
		b, err := os.ReadFile(*keyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read:", err)
			os.Exit(1)
		}
		block, _ := pem.Decode(b)
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			fmt.Fprintln(os.Stderr, "parse:", err)
			os.Exit(1)
		}
		sig, err := ecdsa.SignASN1(rand.Reader, k.(*ecdsa.PrivateKey), []byte(*challenge))
		if err != nil {
			fmt.Fprintln(os.Stderr, "sign:", err)
			os.Exit(1)
		}
		fmt.Println(base64.RawURLEncoding.EncodeToString(sig))
	default:
		flag.Usage()
		os.Exit(2)
	}
}
