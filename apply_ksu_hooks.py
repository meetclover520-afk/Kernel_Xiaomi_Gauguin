#!/usr/bin/env python3
"""
apply_ksu_hooks.py — SukiSU-Ultra builtin Manual Hook 注入器 v4
================================================================
目标: Linux 4.19 QCOM SM7225 非 GKI (gauguin/gauguinpro)

【问题根因 — 已通过编译日志与运行现象确认】

  现象:  旧内核授权过的 app / LSPosed 仍然有 root 且正常工作，
         但 SukiSU-Ultra 管理器显示"内核上未检测到驱动"。

  原因:  SukiSU-Ultra 的 execve hook 有两条并行路径:
           ① ksu_execveat_hook = false → ksu_handle_execveat_sucompat()
                  职责: ksud "首次向内核注册自己"
                        ksud 写入 *flags 通知内核注册完成
                        内核收到后将 ksu_execveat_hook 翻转为 true
           ② ksu_execveat_hook = true  → ksu_handle_execveat()
                  职责: 日常 su 授权 (检查 /data/adb/ksu/packages.json)

  错误版本 (v1/v2 注入在 do_execve):
       ksu_handle_execveat_sucompat((int *)AT_FDCWD, ..., NULL)
                                    ^^^^^^^^^^^^^^^^      ^^^^
       - (int*)AT_FDCWD = 把整数 -100 强转为指针，无效内存地址
       - NULL = ksud 无法通过 flags 回传注册完成信号
       
  导致结果:
       - ksu_execveat_hook 永远不翻转 (sucompat 一直被调用)
       - sucompat 路径能处理普通 su 调用 → 旧 app root 正常 ✓
       - ksud 注册失败 → 管理器无法与内核通信 → "检测不到驱动" ✗

  正确做法 (官方文档规定):
       hook 必须在 do_execveat_common() 内，使用真实参数地址:
       ksu_handle_execveat_sucompat(&fd, ..., &flags)
                                    ^^^        ^^^^^^
       - &fd    = do_execveat_common 的 int fd 参数，有效地址 ✓
       - &flags = do_execveat_common 的 int flags 参数，有效地址 ✓
       - ksud 能写入 *flags 完成注册 → ksu_execveat_hook = true ✓
       - 管理器正常检测到驱动 ✓

【特征串精确匹配策略】
  v2 使用 "ksu_handle_execveat_sucompat"       → 误匹配旧错误版本
  v3/v4 使用 "ksu_handle_execveat_sucompat(&fd," → 仅匹配正确版本
  旧版含 "(int *)AT_FDCWD" 或 "NULL)" → 不匹配 → 强制清除重注入

【Regex 安全性改进 (v4)】
  旧: func_re + r'[^{]+\{'
      风险: 若文件有前向声明，[^{]+ 会跨越声明末尾的;一路匹配到
            其他函数的 {，导致 extern/hook 注入到错误位置。

  新: func_re + r'\s*\([^)]+\)\s*\{'
      原理: \([^)]+\) 精确匹配参数列表（圆括号内不能有闭合），
            再接 \s*\{ 匹配开括号（允许参数列表结尾到{之间有换行）。
            前向声明以 ; 结尾，不含 { → 不会被误匹配。
"""

import re, sys, os

R="\033[31m"; G="\033[32m"; Y="\033[33m"; B="\033[34m"; RESET="\033[0m"
def ok(m):   print(f"{G}[OK]{RESET}    {m}")
def err(m):  print(f"{R}[ERR]{RESET}   {m}"); sys.exit(1)
def warn(m): print(f"{Y}[WARN]{RESET}  {m}")
def info(m): print(f"{B}[INFO]{RESET}  {m}")

# ─────────────────────────────────────────────────────────────
# 精确特征串：仅当 hook 在 do_execveat_common 且参数正确时才匹配
# ─────────────────────────────────────────────────────────────
SIGS = {
    "fs/exec.c":              "ksu_handle_execveat_sucompat(&fd,",   # &fd 而非 AT_FDCWD
    "fs/open.c":              "ksu_handle_faccessat(&dfd,",
    "fs/read_write.c":        "ksu_vfs_read_hook __read_mostly",
    "fs/stat.c":              "ksu_handle_stat(&dfd,",
    "drivers/input/input.c":  "ksu_handle_input_handle_event(&type,",
}

def purge(content, fp):
    """删除文件中所有 #ifdef CONFIG_KSU ... #endif 块"""
    pat = re.compile(r'\n?[ \t]*#ifdef CONFIG_KSU\b.*?#endif[^\n]*', re.DOTALL)
    c, n = pat.subn('', content)
    if n: warn(f"清除 {fp} 中 {n} 个旧 CONFIG_KSU 块")
    return c

def find_func(content, name_re, fp):
    """
    安全地定位函数定义（不误匹配前向声明）。
    使用 \([^)]+\)\s*\{ 匹配参数列表+开括号，而非 [^{]+\{。
    """
    pattern = name_re + r'\s*\([^)]+\)\s*\{'
    m = re.search(pattern, content, re.DOTALL)
    if not m:
        err(
            f"未找到函数 [{name_re}]\n"
            f"  文件: {fp}\n"
            f"  请确认内核源码为 gauguin SM7225 Linux 4.19 标准结构"
        )
    return m

def inject(fp, name_re, ext_code, hook_code):
    """
    1. 精确特征检测：已正确注入则跳过
    2. 发现旧版/错误版本：强制清除
    3. 用 find_func 定位函数（安全 regex）
    4. extern 声明注入到函数定义之前（文件作用域）
    5. hook 调用注入到函数体开头（{之后）
    """
    if not os.path.exists(fp): err(f"文件不存在: {fp}")
    c = open(fp, encoding="utf-8", errors="replace").read()

    sig = SIGS.get(fp, "")
    if sig and sig in c:
        info(f"已是正确版本，跳过: {fp}")
        return

    if "#ifdef CONFIG_KSU" in c:
        warn(f"发现旧版/错误 hook → 强制清除重注入: {fp}")
        c = purge(c, fp)

    m = find_func(c, name_re, fp)
    p = m.end()    # { 之后的位置（注入 hook）
    s = m.start()  # 函数定义起始（注入 extern）

    # 先注入 hook（位置 p，在 s 之后，不影响 s）
    c = c[:p] + "\n" + hook_code + c[p:]
    # 再注入 extern（位置 s，插入不改变 s 之前的内容）
    c = c[:s] + ext_code + "\n" + c[s:]

    open(fp, "w", encoding="utf-8").write(c)
    ok(f"注入: {fp}")

# ══════════════════════════════════════════════════════════════
# Hook 代码
# ══════════════════════════════════════════════════════════════

# ── fs/exec.c → do_execveat_common ────────────────────────────
# 核心修正：do_execveat_common 拥有真实的 int fd / int flags 参数
# 传 &fd 和 &flags，ksud 能正常完成自注册
EXEC_EXT = """\
#ifdef CONFIG_KSU
extern bool ksu_execveat_hook __read_mostly;
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,
\t\t\tvoid *argv, void *envp, int *flags);
extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
\t\t\tvoid *argv, void *envp, int *flags);
#endif"""

EXEC_HOOK = """\
\t/* SukiSU-Ultra builtin: ksud 自注册走 sucompat 路径，&fd &flags 必须为有效地址 */
#ifdef CONFIG_KSU
\tif (unlikely(ksu_execveat_hook))
\t\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
\telse
\t\tksu_handle_execveat_sucompat(&fd, &filename, &argv, &envp, &flags);
#endif"""

# ── fs/open.c → do_faccessat ──────────────────────────────────
OPEN_EXT = """\
#ifdef CONFIG_KSU
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
\t\t\tint *mode, int *flags);
#endif"""

OPEN_HOOK = """\
\t/* SukiSU-Ultra builtin: ksud 通信通道 */
#ifdef CONFIG_KSU
\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);
#endif"""

# ── fs/read_write.c → vfs_read ────────────────────────────────
RW_EXT = """\
#ifdef CONFIG_KSU
extern bool ksu_vfs_read_hook __read_mostly;
extern int ksu_handle_vfs_read(struct file **file_ptr, char __user **buf_ptr,
\t\t\tsize_t *count_ptr, loff_t **pos);
#endif"""

RW_HOOK = """\
\t/* SukiSU-Ultra builtin: /proc 路径读取拦截 */
#ifdef CONFIG_KSU
\tif (unlikely(ksu_vfs_read_hook))
\t\tksu_handle_vfs_read(&file, &buf, &count, &pos);
#endif"""

# ── fs/stat.c → vfs_statx ─────────────────────────────────────
STAT_EXT = """\
#ifdef CONFIG_KSU
extern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);
#endif"""

STAT_HOOK = """\
\t/* SukiSU-Ultra builtin: stat 路径检测 */
#ifdef CONFIG_KSU
\tksu_handle_stat(&dfd, &filename, &flags);
#endif"""

# ── drivers/input/input.c → input_handle_event ────────────────
INPUT_EXT = """\
#ifdef CONFIG_KSU
extern bool ksu_input_hook __read_mostly;
extern int ksu_handle_input_handle_event(unsigned int *type,
\t\t\tunsigned int *code, int *value);
#endif"""

INPUT_HOOK = """\
#ifdef CONFIG_KSU
\tif (unlikely(ksu_input_hook))
\t\tksu_handle_input_handle_event(&type, &code, &value);
#endif"""


def patch_input():
    """input.c 单独处理：hook 放在 disposition 计算之后"""
    fp = "drivers/input/input.c"
    if not os.path.exists(fp): err(f"文件不存在: {fp}")
    c = open(fp, encoding="utf-8", errors="replace").read()

    if SIGS[fp] in c:
        info(f"已是正确版本，跳过: {fp}"); return
    if "#ifdef CONFIG_KSU" in c:
        warn(f"旧版 hook → 清除: {fp}"); c = purge(c, fp)

    m = find_func(c, r"static\s+void\s+input_handle_event\b", fp)
    # extern 在函数前
    c = c[:m.start()] + INPUT_EXT + "\n\n" + c[m.start():]
    # hook 在 disposition 之后（重新搜索，因为内容已变）
    anchor = "int disposition = input_get_disposition(dev, type, code, &value);"
    if anchor not in c: err(f"未找到 disposition 锚点: {fp}")
    c = c.replace(anchor, anchor + "\n" + INPUT_HOOK, 1)

    open(fp, "w", encoding="utf-8").write(c)
    ok(f"注入: {fp}")


def verify():
    print()
    all_ok = True
    for fp, sig in SIGS.items():
        if not os.path.exists(fp): err(f"不存在: {fp}")
        c = open(fp, encoding="utf-8", errors="replace").read()
        if sig in c:
            ok(f"验证: {fp}  ← [{sig}]")
        else:
            warn(f"验证失败: {fp}  期望: [{sig}]")
            all_ok = False
    return all_ok


def main():
    print(f"\n{B}{'='*62}{RESET}")
    print( "  SukiSU-Ultra builtin Hook 注入器 v4")
    print( "  exec hook → do_execveat_common(&fd, &flags)  [已修正]")
    print(f"{B}{'='*62}{RESET}\n")

    inject("fs/exec.c",
           r"static\s+int\s+do_execveat_common\b",
           EXEC_EXT, EXEC_HOOK)

    inject("fs/open.c",
           r"long\s+do_faccessat\b",
           OPEN_EXT, OPEN_HOOK)

    inject("fs/read_write.c",
           r"ssize_t\s+vfs_read\b",
           RW_EXT, RW_HOOK)

    inject("fs/stat.c",
           r"int\s+vfs_statx\b",
           STAT_EXT, STAT_HOOK)

    patch_input()

    if verify():
        print(); ok("全部 Hook 注入并验证完成！")
        print(f"\n  {B}下次编译 ksud 将正确完成自注册，管理器应显示\"驱动已激活\"{RESET}\n")
    else:
        err("验证失败，请检查上方错误信息")


if __name__ == "__main__":
    main()
