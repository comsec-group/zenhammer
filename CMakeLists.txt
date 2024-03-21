cmake_minimum_required(VERSION 3.16)

project(dare)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-O2 -Wall -Wextra -Werror")

add_executable(dare
        src/analyzer.cpp
        src/dare.cpp
        src/memory.cpp
        src/pagemap.cpp
        src/solver.cpp
        src/utils.cpp
        )

target_include_directories(dare PRIVATE "${CMAKE_SOURCE_DIR}/external")
