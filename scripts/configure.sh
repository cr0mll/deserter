#! /bin/bash

cmake -D SUPPORT_MULTIPLE_QUERIES=$1 -D CMAKE_BUILD_TYPE=Release -S .. -B ../build