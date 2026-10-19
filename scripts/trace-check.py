#!/usr/bin/env python3
"""V-7 追溯对账（C-1 编号闭合的工程卡点）。

为什么：SRS §9 追溯矩阵靠人工维护，代码新增包/文件若不携带 FR/WP/IR 编号，
矩阵与代码即漂移（孤儿需求反向形态=孤儿代码）。本脚本做最低限度的机械对账：

  每个 platform/services 下的 Go 包（目录）必须有「带需求编号的包注释」——
  即包文档注释中出现 FR-/WP-/IR-/CR-/ENH- 之一的编号引用。

用法：python3 scripts/trace-check.py（CI 同步执行；退出码非 0=对账失败）
范围：仅查包级 doc comment（每个目录取首个非测试 .go 文件的包注释），
      不做行级穷举（避免把注释里提及编号误判为「该文件已追溯」）。
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "platform" / "services"
ID_RE = re.compile(r"\b(FR|WP|IR|CR|ENH)-[A-Za-z0-9-]+")
PKG_RE = re.compile(r"^package\s+\w+", re.M)


def pkg_doc_has_id(path: Path) -> bool:
    try:
        src = path.read_text(encoding="utf-8")
    except OSError as exc:  # noqa: BLE001
        print(f"  ✗ 读取失败 {path}: {exc}")
        return False
    m = PKG_RE.search(src)
    if not m:
        print(f"  ✗ 无 package 声明: {path}")
        return False
    doc = src[: m.start()]
    return bool(ID_RE.search(doc))


def main() -> int:
    if not ROOT.is_dir():
        print(f"trace-check: 目录不存在 {ROOT}")
        return 1
    bad = []
    checked = 0
    for d in sorted(p for p in ROOT.rglob("*") if p.is_dir()):
        gos = sorted(d.glob("*.go"))
        first = next((g for g in gos if not g.name.endswith("_test.go")), None)
        if first is None:  # 仅测试文件的目录跳过（无包注释可查）
            continue
        checked += 1
        if not pkg_doc_has_id(first):
            bad.append(first.relative_to(ROOT.parent.parent))
    print(f"trace-check: 检查 {checked} 个包，缺需求编号注释 {len(bad)} 个")
    for b in bad:
        print(f"  ✗ {b}（包注释须含 FR-/WP-/IR-/CR-/ENH- 编号，C-1）")
    if bad:
        print("TRACE CHECK FAIL：新增包未回写追溯编号（SRS §9 矩阵与代码已漂移）")
        return 1
    print("TRACE CHECK OK（C-1 编号闭合机械对账通过）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
