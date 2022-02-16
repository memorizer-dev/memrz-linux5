#!/bin/bash

source $(dirname "$0")/CLANG_FLAGS

make $CLANG_FLAGS defconfig
# echo "CONFIG_XNSDETECTOR=y" >> .config