// Package rbac 实现 8 角色最小权限矩阵与租户 Scope 判定（PRD F17.1 / FR-TEN-005）。
package rbac

import "errors"

type Permission string

const (
	PermReadAssets    Permission = "read_assets"
	PermWriteAssets   Permission = "write_assets"
	PermManageTenants Permission = "manage_tenants"
	PermNotify        Permission = "notify" // 通报动作；高危执行仍需 M2 审批门禁
	PermReadAudit     Permission = "read_audit"
)

var (
	ErrForbidden   = errors.New("rbac: permission denied")
	ErrCrossTenant = errors.New("rbac: cross-tenant access denied")
)

// Principal 是调用主体：人类角色 R1..R7 或 AI Agent（R8）。
type Principal struct {
	UserID    string
	Role      string
	TenantIDs []string // 授权租户列表；"*" 为全部，仅限管理角色
}

// rolePerms 为 8 角色矩阵 M0 最小版（R1 含红队视角变体；完整矩阵在 M1 扩展并接入视图）。
var rolePerms = map[string][]Permission{
	"R1": {PermReadAssets, PermWriteAssets, PermReadAudit},
	"R2": {PermReadAssets, PermWriteAssets},
	"R3": {PermReadAssets},
	"R4": {PermReadAssets, PermNotify, PermReadAudit},
	"R5": {PermReadAssets},
	"R6": {PermReadAssets, PermWriteAssets},
	"R7": {PermReadAssets, PermWriteAssets, PermManageTenants, PermReadAudit, PermNotify}, // 平台管理员全权（批八补：告警出口 dispatch 需 Notify）
	"R8": {PermReadAssets, PermWriteAssets, PermNotify},
}

func (p Principal) Can(perm Permission) bool {
	for _, q := range rolePerms[p.Role] {
		if q == perm {
			return true
		}
	}
	return false
}

// InScope 是行级隔离的第一道闸：一票否决④的判定入口。
func (p Principal) InScope(tenantID string) bool {
	for _, t := range p.TenantIDs {
		if t == "*" || t == tenantID {
			return true
		}
	}
	return false
}
