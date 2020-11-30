include(CheckCXXCompilerFlag)
cmake_minimum_required(VERSION 3.10)
project(blacksmith VERSION 0.0.1 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 11)

# Add some compiler options if they are supported
function(enable_cxx_compiler_flag_if_supported flag)
    string(FIND "${CMAKE_CXX_FLAGS}" "${flag}" flag_already_set)
    if (flag_already_set EQUAL -1)
        check_cxx_compiler_flag("${flag}" flag_supported)
        if (flag_supported)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}" PARENT_SCOPE)
        endif ()
        unset(flag_supported CACHE)
    endif ()
endfunction()
enable_cxx_compiler_flag_if_supported("-Wall")
enable_cxx_compiler_flag_if_supported("-Wextra")

# Dependency: Asmjit
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/Modules" ${CMAKE_MODULE_PATH})
find_package(ASMJIT)
if (NOT ASMJIT_FOUND)
    message("Please download and install asmjit using this one-liner: git clone https://github.com/asmjit/asmjit && cd asmjit && cmake . && make && sudo make install && sudo ldconfig")
endif ()

set(SOURCES
        src/Fuzzer/CodeJitter.cpp
        src/DRAMAddr.cpp
        src/DramAnalyzer.cpp
        src/Fuzzer/PatternBuilder.cpp
        src/PatternAddressMapper.cpp
        src/Utilities/Memory.cpp
        src/Fuzzer/FuzzingParameterSet.cpp)

set(LIBRARY_NAME libblacksmith)
add_library(${LIBRARY_NAME} OBJECT ${SOURCES})
target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(${LIBRARY_NAME} PUBLIC asmjit)

add_executable(blacksmith src/Blacksmith.cpp include/Blacksmith.hpp)
target_link_libraries(blacksmith PRIVATE ${LIBRARY_NAME})

