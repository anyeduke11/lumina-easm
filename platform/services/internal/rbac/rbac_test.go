package rbac

import "testing"

// 为什么：R8 是外部接入的 Agent，不可信主体不得管理租户/读审计——
// 这是 AX-5「人在环」与 PRD R10「越权拒绝」的边界，若本用例能常绿则角色矩阵失去意义。
func TestRoleMatrixDeniesAgentAdminPowers(t *testing.T) {
	agent := Principal{UserID: "agent-1", Role: "R8", TenantIDs: []string{"t-a"}}
	if agent.Can(PermManageTenants) {
		t.Error("R8 Agent 不应有 manage_tenants 权限")
	}
	if agent.Can(PermReadAudit) {
		t.Error("R8 Agent 不应有 read_audit 权限")
	}
	if !agent.Can(PermReadAssets) {
		t.Error("R8 Agent 应能读资产（MCP 消费场景）")
	}

	admin := Principal{UserID: "u7", Role: "R7"}
	if !admin.Can(PermManageTenants) {
		t.Error("R7 平台管理员应有 manage_tenants 权限")
	}

	viewer := Principal{UserID: "u5", Role: "R5"}
	if viewer.Can(PermWriteAssets) {
		t.Error("R5 情报分析师不应有 write_assets 权限")
	}
}

// 为什么：InScope 是行级隔离的第一道闸（FR-TEN-005 / 一票否决④）。
// "*" 仅限管理角色使用。
func TestInScopeWildcard(t *testing.T) {
	all := Principal{Role: "R7", TenantIDs: []string{"*"}}
	if !all.InScope("any-tenant") {
		t.Error("* 应命中任意租户")
	}
	scoped := Principal{Role: "R1", TenantIDs: []string{"t-a"}}
	if scoped.InScope("t-b") {
		t.Error("限定 t-a 的主体不应命中 t-b")
	}
	if !scoped.InScope("t-a") {
		t.Error("限定 t-a 的主体应命中 t-a")
	}
}
