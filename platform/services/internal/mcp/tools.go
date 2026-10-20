package mcp

// M4-04 / WP-M4-04 向量库导出面（F12/AIL-9）：知识库条目（漏洞+情报）的
// 向量化导出形状。ENH-02 向量库本体未装配——导出面按「如实返空」边界先行：
// items 为可向量化文本载荷（确定性知识），vector_store=not_configured、
// ingested=false 如实标注，不冒充已入库检索能力（fail loud 优于伪造）。

import (
	"github.com/wangdev88/easm-platform/platform/services/internal/intel"
	"github.com/wangdev88/easm-platform/platform/services/internal/vuln"
)

type knowledgeExport struct {
	VectorStore string         `json:"vector_store"` // not_configured（ENH-02 未装）
	Ingested    bool           `json:"ingested"`
	Basis       string         `json:"basis"`
	Vulns       []vuln.Entry   `json:"vulns"`
	Intel       []intel.Entry  `json:"intel"`
	Counts      map[string]int `json:"counts"`
}

func (s *Server) knowledgeExport() knowledgeExport {
	out := knowledgeExport{
		VectorStore: "not_configured",
		Basis: "WP-M4-04/AIL-9：导出面先行（确定性知识条目可下游消费）；ENH-02 向量库本体未装配=" +
			"不返回 embedding、不宣称已向量化检索（如实标注能力边界）",
		Counts: map[string]int{},
	}
	if s.vulns != nil {
		out.Vulns = s.vulns.List("", "")
		out.Counts["vulns"] = len(out.Vulns)
	}
	if s.intels != nil {
		out.Intel = s.intels.List("", "")
		out.Counts["intel"] = len(out.Intel)
	}
	return out
}
