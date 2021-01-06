include(CheckCXXCompilerFlag)

cmake_minimum_required(VERSION 3.14)
project(blacksmith VERSION 0.0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE DEBUG)

option(ENABLE_JSON "Add functionality for JSON export using nlohmann/json library." OFF)
option(ENABLE_JITTING "Add functionality for jitting the hammering code using asmjit library." OFF)

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
enable_cxx_compiler_flag_if_supported("-Wno-unused-parameter")

set(SOURCES
        Fuzzer/Aggressor.cpp
        DRAMAddr.cpp
        DramAnalyzer.hpp
        Fuzzer/PatternBuilder.cpp
        Fuzzer/FuzzingParameterSet.cpp
        Fuzzer/AggressorAccessPattern.cpp)

set(HEADER_ONLY
        Fuzzer/PatternAddressMapping.hpp
        Memory.hpp
        GlobalDefines.hpp)

set(LIBRARY_NAME libblacksmith)
add_library(${LIBRARY_NAME} ${SOURCES} ${HEADER_ONLY})
target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR})

#add_executable(blacksmith Blacksmith.hpp bs.cpp bs.h)
#target_link_libraries(blacksmith PRIVATE ${LIBRARY_NAME})
