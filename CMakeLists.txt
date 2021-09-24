cmake_minimum_required(VERSION 3.18.4)

project(deserter)

add_subdirectory(src)
add_subdirectory(external/PcapPlusPlus)
add_subdirectory(external/argparse)

set(CMAKE_CXX_STANDARD 17)
set(PACKETPP_LIB_PATH "${PROJECT_SOURCE_DIR}external/PcapPlusPlus/Packet++")
set(COMMONPP_LIB_PATH "${PROJECT_SOURCE_DIR}/external/PcapPlusPlus/Common++")
set(PCAPPP_LIB_PATH "${PROJECT_SOURCE_DIR}/external/PcapPlusPlus/Pcap++")


include_directories(
        /include
        /src
)
file(GLOB sources
        "${PROJECT_SOURCE_DIR}/src/*.h"
        "${PROJECT_SOURCE_DIR}/src/*.hpp"
        "${PROJECT_SOURCE_DIR}/src/*.cpp"
        "${PROJECT_SOURCE_DIR}/src/*.c"
)

add_compile_definitions(${SUPPORT_MULTIPLE_QUERIES})

get_directory_property( DirDefs DIRECTORY ${CMAKE_SOURCE_DIR} COMPILE_DEFINITIONS )
foreach( d ${DirDefs} )
    message( STATUS "Found Define: " ${d} )
endforeach()
message( STATUS "DirDefs: " ${DirDefs} )

add_executable(${PROJECT_NAME} ${sources})

target_include_directories(${PROJECT_NAME} 
        PUBLIC ${PACKETPP_LIB_PATH}/header
        PUBLIC ${COMMONPP_LIB_PATH}/header
        PUBLIC ${PCAPPP_LIB_PATH}/header
        PUBLIC ${PROJECT_SOURCE_DIR}/external/argparse)

target_link_directories(${PROJECT_NAME}
        PRIVATE ${PACKETPP_LIB_PATH}/src
        PRIVATE ${COMMONPP_LIB_PATH}/src
        PRIVATE ${PCAPPP_LIB_PATH}/src
        PRIVATE ${PROJECT_SOURCE_DIR}/build/external/PcapPlusPlus/lib
        PRIVATE ${PROJECT_SOURCE_DIR}/build/external/PcapPlusPlus/3rdParty/LightPcapNg
        PRIVATE ${PROJECT_SOURCE_DIR}/external/argparse
        PRIVATE ${PROJECT_SOURCE_DIR}/src)

target_link_libraries(${PROJECT_NAME} CommonPP PacketPP PcapPP light_pcapng)

message(STATUS "libs: ${LINK_LIBRARIES}")
