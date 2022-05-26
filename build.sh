#!/bin/sh
mkdir -p build
cd build
cmake -D CMAKE_BUILD_TYPE=Release -G "Unix Makefiles" ..
make VERBOSE=1
