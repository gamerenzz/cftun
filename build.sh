#!/bin/bash

set -e  # 发生错误时退出

APP_NAME="cftun"
VERSION="2.3.0"
BUILD_TYPE="release"
BUILD_DIR="build"
PLATFORMS=("windows/amd64")

# 创建 build 目录
mkdir -p $BUILD_DIR

# 交叉编译
for PLATFORM in "${PLATFORMS[@]}"; do
    OS=${PLATFORM%%/*}
    ARCH=${PLATFORM##*/}

    OUTPUT_NAME="$APP_NAME-$OS-$ARCH"
    if [ "$OS" == "windows" ]; then
        OUTPUT_NAME+=".exe"
    fi

    echo "Building only for $OS/$ARCH (Hiding Console Window)..."
    # -H windowsgui 标志：在 Windows 下运行不弹出黑色命令行窗口，直接进入纯 GUI 进程
    LDFLAGS="-H windowsgui -X main.Version=$VERSION -X main.BuildDate=$(date '+%Y-%m-%d_%H:%M:%S_%Z') -X main.BuildType=$BUILD_TYPE"

    env CGO_ENABLED=0 GOOS=$OS GOARCH=$ARCH go build -ldflags "$LDFLAGS" -o $BUILD_DIR/$OUTPUT_NAME

    # 压缩打包
    if [ "$OS" == "windows" ]; then
        zip -j "$BUILD_DIR/$APP_NAME-$OS-$ARCH.zip" "$BUILD_DIR/$OUTPUT_NAME"
    else
        tar -czvf "$BUILD_DIR/$APP_NAME-$OS-$ARCH.tar.gz" -C "$BUILD_DIR" "$OUTPUT_NAME"
    fi
done

echo "Build completed! Windows binary is in the '$BUILD_DIR' directory."
