#!/bin/bash

# Copy the cmake files to the appropriate locations
cp setup/lists/3rdParty.txt ../external/PcapPlusPlus/3rdParty/CMakeLists.txt
cp setup/lists/EndianPortable.txt ../external/PcapPlusPlus/3rdParty/EndianPortable/CMakeLists.txt
cp setup/lists/hash-library.txt ../external/PcapPlusPlus/3rdParty/hash-library/CMakeLists.txt
cp setup/lists/lightpcapng.txt ../external/PcapPlusPlus/3rdParty/LightPcapNg/CMakeLists.txt
cp setup/lists/lightpcapng-inner.txt ../external/PcapPlusPlus/3rdParty/LightPcapNg/LightPcapNg/CMakeLists.txt

cp setup/lists/Common++.txt ../external/PcapPlusPlus/Common++/CMakeLists.txt
cp setup/lists/Packet++.txt ../external/PcapPlusPlus/Packet++/CMakeLists.txt
cp setup/lists/Pcap++.txt ../external/PcapPlusPlus/Pcap++/CMakeLists.txt
cp setup/lists/PcapPlusPlus.txt ../external/PcapPlusPlus/CMakeLists.txt

# Copy the cmake modules
mkdir ../external/PcapPlusPlus/cmake
mkdir ../external/PcapPlusPlus/cmake/Modules

cp setup/modules/DetectCompiler ../external/PcapPlusPlus/cmake/Modules/DetectCompiler.cmake
cp setup/modules/DetectOS ../external/PcapPlusPlus/cmake/Modules/DetectOS.cmake
cp setup/modules/FindDPDK ../external/PcapPlusPlus/cmake/Modules/FindDPDK.cmake
cp setup/modules/FindNUMA ../external/PcapPlusPlus/cmake/Modules/FindNUMA.cmake
cp setup/modules/FindPCAP ../external/PcapPlusPlus/cmake/Modules/FindPCAP.cmake
cp setup/modules/FindPF_Ring ../external/PcapPlusPlus/cmake/Modules/FindPF_Ring.cmake
