#!/bin/bash

# 切换到 miracl_core/cpp 目录
cd "$(dirname "$0")/miracl_core/cpp" || exit 1

# 自动输入曲线编号并运行配置脚本
echo -e "31\n0\n" | python3 config64.py