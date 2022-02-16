#!/bin/bash

THIS_DIR=$(dirname "$0")
source $THIS_DIR/CLANG_FLAGS

if [ ! -f .config ]; then
    source gen_config.sh
fi

make $CLANG_FLAGS -j$(nproc) 2>&1 | tee $THIS_DIR/build.log