#! /bin/bash

cmake -D SUPPORT_MULTIPLE_QUERIES=$1 -S .. -B ../build