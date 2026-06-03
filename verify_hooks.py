#!/usr/bin/env python3
"""
verify_hooks.py — 在内核源码目录中验证/预览 Hook 注入结果
不修改任何文件，只读取并报告当前状态。
使用方式: cd <kernel_source_root> && python3 verify_hooks.py
"""
import re, os, sys

G="\033[32m"; R="\033[31m"; Y="\033[33m"; B="\033[34m"; RESET="\033[0m"

CHECKS = {
    "fs/exec.c": {
        "correct_v4":  "ksu_handle_execveat_sucompat(&fd,",
        "wrong_v1v2":  "ksu_handle_execveat_sucompat((int *)AT_FDCWD",
        "wrong_null":  "ksu_handle_execveat_sucompat((int *)AT_FDCWD, &filename, &argv,\n\t\t\t\t\t     &envp, NULL)",
        "func_exists": "do_execveat_common",
    },
    "fs/open.c": {
        "correct_v4": "ksu_handle_faccessat(&dfd,",
        "func_exists": "do_faccessat",
    },
    "fs/read_write.c": {
        "correct_v4": "ksu_vfs_read_hook __read_mostly",
        "func_exists": "vfs_read",
    },
    "fs/stat.c": {
        "correct_v4": "ksu_handle_stat(&dfd,",
        "func_exists": "vfs_statx",
    },
    "drivers/input/input.c": {
        "correct_v4": "ksu_handle_input_handle_event(&type,",
        "func_exists": "input_handle_event",
    },
}

def check_file(fp, checks):
    if not os.path.exists(fp):
        print(f"  {R}[MISSING]{RESET} {fp}")
        return False

    c = open(fp, encoding="utf-8", errors="replace").read()
    print(f"\n  {B}── {fp}{RESET}")

    # 函数是否存在
    if "func_exists" in checks:
        fn = checks["func_exists"]
        if fn in c:
            print(f"    {G}[✓]{RESET} 函数 {fn} 存在")
        else:
            print(f"    {R}[✗]{RESET} 函数 {fn} 不存在！内核结构可能不同")

    # 正确版本检测
    cv4 = checks.get("correct_v4", "")
    if cv4 and cv4 in c:
        print(f"    {G}[✓]{RESET} 已注入正确版本 (v4)  [{cv4}]")

        # 验证 exec.c 的 hook 确实在 do_execveat_common 内
        if fp == "fs/exec.c":
            m_func = re.search(
                r"static\s+int\s+do_execveat_common\s*\([^)]+\)\s*\{",
                c, re.DOTALL
            )
            hook_pos = c.find(cv4)
            if m_func and hook_pos > m_func.end():
                print(f"    {G}[✓]{RESET} Hook 位于 do_execveat_common 函数体内 ✓")
            elif m_func:
                print(f"    {R}[✗]{RESET} Hook 不在 do_execveat_common 内！位置异常")
            return True
        return True

    # 错误版本检测
    wrong = checks.get("wrong_v1v2", "")
    if wrong and wrong in c:
        print(f"    {R}[✗]{RESET} 发现旧版/错误 hook (AT_FDCWD 强转指针 + NULL flags)")
        print(f"          运行 apply_ksu_hooks.py v4 会自动清除并重注入")
        return False

    # 无 hook
    if "#ifdef CONFIG_KSU" not in c:
        print(f"    {Y}[?]{RESET} 未发现任何 CONFIG_KSU 块，hook 尚未注入")
    else:
        print(f"    {Y}[?]{RESET} 有 CONFIG_KSU 块但特征串不匹配，可能是其他版本")
    return False


def check_defconfig():
    dc = "arch/arm64/configs/vendor/gauguin_user_defconfig"
    if not os.path.exists(dc):
        print(f"  {R}[MISSING]{RESET} {dc}")
        return

    c = open(dc).read()
    print(f"\n  {B}── {dc}{RESET}")
    for opt in ["CONFIG_KSU=y", "CONFIG_KSU_MANUAL_HOOK=y",
                "CONFIG_KALLSYMS=y", "CONFIG_KALLSYMS_ALL=y"]:
        if opt in c:
            print(f"    {G}[✓]{RESET} {opt}")
        else:
            print(f"    {R}[✗]{RESET} {opt}  ← 缺失！")


def main():
    print(f"\n{B}{'='*60}{RESET}")
    print( "  SukiSU-Ultra Hook 状态验证工具")
    print( "  (只读，不修改任何文件)")
    print(f"{B}{'='*60}{RESET}")

    all_ok = True
    for fp, checks in CHECKS.items():
        if not check_file(fp, checks):
            all_ok = False

    check_defconfig()

    print()
    if all_ok:
        print(f"{G}[结论]{RESET} 所有 Hook 已正确注入，编译后管理器应能正常检测驱动")
    else:
        print(f"{R}[结论]{RESET} 发现问题，请运行 apply_ksu_hooks.py v4 修复")
    print()


if __name__ == "__main__":
    main()
