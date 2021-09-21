cmake_minimum_required(VERSION 3.18.4)

project(deserter)

add_subdirectory(src)
add_subdirectory(external/PcapPlusPlus)

include_directories(
        /include
        /src
)
file(GLOB sources
        "./include/*.h"
        "./include/*.hpp"
        "./src/*.cpp"
        "./src/*.c"
)

add_executable(${PROJECT_NAME} ${sources})