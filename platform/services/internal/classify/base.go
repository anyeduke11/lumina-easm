// Package classify 基础类型与工具函数（引擎入口见 engine.go，规则见 rules.go）。
// 判敏引擎=三类敏感数据 34 项 / 22 条规则的确定性实现（FR-CLS-001~007 / WP-M1-03）。
package classify

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

const (
	CatSys  = "系统架构类"
	CatCred = "代码密码类"
	CatBiz  = "业务经营类"
)

// Input 结构化通道（FR-DSC-014/016 联动）：扫描器字段直接喂给对应规则。
type Input struct {
	URL   string   `json:"url,omitempty"`
	Ports []int    `json:"ports,omitempty"`
	Tech  []string `json:"tech,omitempty"`
	Title string   `json:"title,omitempty"`
}

// Hit 命中即证据（FR-CLS-007 可解释）。
type Hit struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Category string `json:"category"`
	Level    string `json:"level"` // 严重/高/中
	Snippet  string `json:"snippet"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
}

type Rule struct {
	ID     string
	Name   string
	Cat    string
	Logic  string // 检测逻辑（FR-CLS 规则明细）
	Method string // 检测方式
	Level  string
	run    func(string, Input) []Hit
}

func re(pat string) *regexp.Regexp { return regexp.MustCompile(pat) }

type subMatch struct {
	s     string
	start int
	end   int
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]int{}
	rs := []rune(s)
	for _, r := range rs {
		freq[r]++
	}
	var h float64
	total := float64(len(rs))
	for _, c := range freq {
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}

// 身份证校验位（FR-CLS-004）：GB 11643 / ISO 7064 MOD 11-2。
var rxID = re(`[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]`)

var (
	idWeights = []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	idCheck   = []byte("10X98765432")
)

func validID(s string) bool {
	if len(s) != 18 {
		return false
	}
	sum := 0
	for i := 0; i < 17; i++ {
		d, err := strconv.Atoi(string(s[i]))
		if err != nil {
			return false
		}
		sum += d * idWeights[i]
	}
	return byte(strings.ToUpper(s)[17]) == idCheck[sum%11]
}

var rxPhone = re(`1[3-9]\d{9}`)
