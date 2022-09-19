#! /bin/bash

chmod +x configure.sh clean.sh build.sh setup.sh

./setup.sh
./clean.sh
./configure.sh
./build.sh