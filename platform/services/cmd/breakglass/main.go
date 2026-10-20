// Package main 生成/校验 break-glass 应急凭据（FR-TEN-005/NFR-SEC-002/AX-5）。
//
// 用法：
//
//	go run ./platform/services/cmd/breakglass -init
//	go run ./platform/services/cmd/breakglass -verify -token BG-... -hash <hex>
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/wangdev88/easm-platform/platform/services/internal/authn"
)

func main() {
	initFlag := flag.Bool("init", false, "生成 token 与 EASM_BREAKGLASS_HASH")
	verifyFlag := flag.Bool("verify", false, "校验 token 与 hash")
	token := flag.String("token", "", "break-glass token（仅离线保管）")
	hash := flag.String("hash", "", "SHA-256 hex")
	flag.Parse()

	switch {
	case *initFlag:
		t, h, err := authn.GenerateBreakGlass()
		if err != nil {
			fmt.Fprintln(os.Stderr, "generate:", err)
			os.Exit(1)
		}
		fmt.Printf("EASM_BREAKGLASS_HASH=%s\n", h)
		fmt.Printf("break-glass token（离线保管，勿入库）: %s\n", t)
	case *verifyFlag:
		bg, err := authn.NewBreakGlass(*hash, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hash:", err)
			os.Exit(1)
		}
		if !bg.Verify(*token) {
			fmt.Fprintln(os.Stderr, "break-glass token 不匹配")
			os.Exit(1)
		}
		fmt.Println("break-glass token OK")
	default:
		flag.Usage()
		os.Exit(2)
	}
}
