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

cp ../install/modules/DetectCompiler.cmake ../external/PcapPlusPlus/cmake/Modules
cp ../install/modules/DetectOS.cmake ../external/PcapPlusPlus/cmake/Modules
cp ../install/modules/FindDPDK.cmake ../external/PcapPlusPlus/cmake/Modules
cp ../install/modules/FindNUMA.cmake ../external/PcapPlusPlus/cmake/Modules
cp ../install/modules/FindPCAP.cmake ../external/PcapPlusPlus/cmake/Modules
cp ../install/modules/FindPF_Ring.cmake ../external/PcapPlusPlus/cmake/Modules

./clean.sh
./configure.sh
./build.sh
