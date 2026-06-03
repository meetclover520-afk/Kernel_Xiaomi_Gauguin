#!/usr/bin/env bash
# =============================================================================
# build.sh — Redmi Note 9 Pro (gauguin, SM7225) SukiSU-Ultra Kernel
# =============================================================================
# 配套 APK: SukiSU-Ultra 最新版
# 下载地址: https://github.com/SukiSU-Ultra/SukiSU-Ultra/releases/latest
#
# 注意: builtin 分支的内核版本号 ≈ 783（该分支的 commit 计数）
#       必须使用 v4.0.0 及以上的 APK，v3.x APK 不兼容（版本号差距过大）
# =============================================================================
set -euo pipefail

export PATH=$GITHUB_WORKSPACE/clang/bin:$GITHUB_WORKSPACE/gcc64/bin:$PATH

# ── ccache ──────────────────────────────────────────────────
export CCACHE_DIR=~/.ccache
export CCACHE_EXEC=$(which ccache)
ccache -M 10G
if [ "${CLEAN_CCACHE:-false}" = "true" ]; then
    echo "[!] 清理 ccache..."
    ccache -C
fi
ccache -z

# ── 1. 清理旧 KernelSU，部署 SukiSU-Ultra builtin ────────────
rm -rf drivers/kernelsu KernelSU

curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" \
    | bash -s builtin

KSU_VER=$(cd KernelSU && git rev-list --count HEAD 2>/dev/null || echo "unknown")
echo "========================================================"
echo "[KSU] 内核版本号: $KSU_VER"
echo "[KSU] 配套 APK : SukiSU-Ultra 最新版 (v4.0.0+)"
echo "[KSU] APK 下载 : https://github.com/SukiSU-Ultra/SukiSU-Ultra/releases/latest"
echo "========================================================"

# ── 2. 注入 Manual Hook ──────────────────────────────────────
python3 apply_ksu_hooks.py

# ── 3. 更新 defconfig ────────────────────────────────────────
DEFCONFIG="arch/arm64/configs/vendor/gauguin_user_defconfig"

for opt in \
    "CONFIG_KSU=y" \
    "CONFIG_KSU_MANUAL_HOOK=y" \
    "CONFIG_KSU_SUSFS=n" \
    "CONFIG_KALLSYMS=y" \
    "CONFIG_KALLSYMS_ALL=y"
do
    KEY="${opt%%=*}"
    sed -i "/^${KEY}[= ]/d; /^# ${KEY} is not set/d" "$DEFCONFIG"
    echo "$opt" >> "$DEFCONFIG"
done

echo "[KSU] defconfig 更新完成"

# ── 4. 提交变更 ──────────────────────────────────────────────
git config --global user.email "ksu-build@localhost"
git config --global user.name  "KSU Build"
git add -A
git commit -m "ksu: SukiSU-Ultra builtin" || true

# ── 5. 编译 ──────────────────────────────────────────────────
args=(
    -j$(nproc --all)
    O=out
    ARCH=arm64
    SUBARCH=arm64
    CC="ccache clang"
    HOSTCC="ccache clang"
    CLANG_TRIPLE=aarch64-linux-gnu-
    CROSS_COMPILE=aarch64-linux-android-
    CROSS_COMPILE_ARM32=arm-linux-gnueabi-
    LLVM=1
)

make "${args[@]}" vendor/gauguin_user_defconfig
make "${args[@]}" Image dtbo.img all

# ── 6. 打包 ──────────────────────────────────────────────────
cp $(find out -type f \( -name "Image" -o -name "dtbo.img" \)) ./
mv -v Image    AnyKernel3/Image
mv -v dtbo.img AnyKernel3/dtbo.img
cat $(find out/arch/arm64/boot/dts/vendor/qcom/ -type f -name "*.dtb") \
    > AnyKernel3/dtb
cd AnyKernel3 && zip -r9v ../out/kernel.zip * && cd ..

echo "================= CCACHE STATS ================="
ccache -s
echo "================================================"
