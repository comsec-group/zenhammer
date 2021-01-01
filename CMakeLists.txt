include(CheckCXXCompilerFlag)

cmake_minimum_required(VERSION 3.14)
project(blacksmith VERSION 0.0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE DEBUG)

option(ENABLE_JSON "Add functionality for JSON export using nlohmann/json library." ON)
option(ENABLE_JITTING "Add functionality for jitting the hammering code using asmjit library." ON)

if (ENABLE_JSON)
    add_definitions(-DENABLE_JSON)
    find_package(nlohmann_json QUIET)
    if (NOT nlohmann_json_FOUND)
        message("Library nlohmann/json not found. Downloading nlohmann_json...")
        include(FetchContent)
        set(JSON_BuildTests OFF CACHE INTERNAL "")
        set(FETCHCONTENT_UPDATES_DISCONNECTED ON)
        FetchContent_Declare(
                nlohmann_json
                GIT_REPOSITORY https://github.com/nlohmann/json.git
                GIT_TAG v3.7.3)
        FetchContent_MakeAvailable(nlohmann_json)
    endif ()
endif ()

if (ENABLE_JITTING)
    add_definitions(-DENABLE_JITTING)
    set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/Modules" ${CMAKE_MODULE_PATH})
    find_package(AsmJit)
    if (NOT ASMJIT_FOUND)
        message("Install asmjit manually: git clone https://github.com/asmjit/asmjit && cd asmjit && cmake . && make && sudo make install && sudo ldconfig")
        message("or set ENABLE_JITTING=OFF in the CMakeLists.txt prior building.")
        return()
    endif ()
endif ()

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
#enable_cxx_compiler_flag_if_supported("-Wno-unused-parameter")
enable_cxx_compiler_flag_if_supported("-Wno-unused-function")
enable_cxx_compiler_flag_if_supported("-Wno-format-security")

execute_process(
        COMMAND git rev-parse HEAD
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE)

set(SOURCES
        src/Fuzzer/Aggressor.cpp
        src/Fuzzer/CodeJitter.cpp
        src/DRAMAddr.cpp
        src/DramAnalyzer.cpp
        src/Fuzzer/PatternBuilder.cpp
        src/Fuzzer/PatternAddressMapping.cpp
        src/Memory.cpp
        src/Fuzzer/FuzzingParameterSet.cpp
        src/Fuzzer/HammeringPattern.cpp
        src/Fuzzer/AggressorAccessPattern.cpp
        src/Fuzzer/BitFlip.cpp
        src/Utilities/Logger.cpp)

set(HEADER_ONLY
        include/Fuzzer/PatternAddressMapping.hpp
        include/GlobalDefines.hpp include/Utilities/Enums.hpp)

set(LIBRARY_NAME bs)
add_library(${LIBRARY_NAME} ${SOURCES} ${HEADER_ONLY})
target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)

if (ENABLE_JITTING)
    target_include_directories(${LIBRARY_NAME} PUBLIC ${ASMJIT_INCLUDE_DIR})
    target_link_libraries(${LIBRARY_NAME} PUBLIC asmjit)
endif()

if (ENABLE_JSON)
    target_link_libraries(${LIBRARY_NAME} PUBLIC nlohmann_json::nlohmann_json)
endif ()

add_executable(blacksmith src/Blacksmith.cpp include/Blacksmith.hpp)
target_link_libraries(blacksmith PRIVATE ${LIBRARY_NAME})
target_compile_definitions(blacksmith PRIVATE "-DGIT_COMMIT_HASH=\"${GIT_COMMIT_HASH}\"")
