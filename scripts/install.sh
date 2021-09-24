#! /bin/bash

chmod +x configure.sh clean.sh build.sh

# Copy the cmake files to the appropriate locations
cp ../install/lists/3rdParty.txt ../external/PcapPlusPlus/3rdParty/CMakeLists.txt
cp ../install/lists/EndianPortable.txt ../external/PcapPlusPlus/3rdParty/EndianPortable/CMakeLists.txt
cp ../install/lists/hash-library.txt ../external/PcapPlusPlus/3rdParty/hash-library/CMakeLists.txt
cp ../install/lists/lightpcapng.txt ../external/PcapPlusPlus/3rdParty/LightPcapNg/CMakeLists.txt
cp ../install/lists/lightpcapng-inner.txt ../external/PcapPlusPlus/3rdParty/LightPcapNg/LightPcapNg/CMakeLists.txt

cp ../install/lists/Common++.txt ../external/PcapPlusPlus/Common++/CMakeLists.txt
cp ../install/lists/Packet++.txt ../external/PcapPlusPlus/Packet++/CMakeLists.txt
cp ../install/lists/Pcap++.txt ../external/PcapPlusPlus/Pcap++/CMakeLists.txt
cp ../install/lists/PcapPlusPlus.txt ../external/PcapPlusPlus/CMakeLists.txt

# Copy the cmake modules
mkdir ../external/PcapPlusPlus/cmake
mkdir ../external/PcapPlusPlus/cmake/Modules

cp ../install/modules/DetectCompiler ../external/PcapPlusPlus/cmake/Modules/DetectCompiler.cmake
cp ../install/modules/DetectOS ../external/PcapPlusPlus/cmake/Modules/DetectOS.cmake
cp ../install/modules/FindDPDK ../external/PcapPlusPlus/cmake/Modules/FindDPDK.cmake
cp ../install/modules/FindNUMA ../external/PcapPlusPlus/cmake/Modules/FindNUMA.cmake
cp ../install/modules/FindPCAP ../external/PcapPlusPlus/cmake/Modules/FindPCAP.cmake
cp ../install/modules/FindPF_Ring ../external/PcapPlusPlus/cmake/Modules/FindPF_Ring.cmake

./clean.sh
./configure.sh $1 # use SUPPORT_MULTIPLE_QUERIES_IN_A_SINGLE_REQUEST to build with multiple queries per request supported
./build.sh
