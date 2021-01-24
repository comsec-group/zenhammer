include(CheckCXXCompilerFlag)

cmake_minimum_required(VERSION 3.14)
project(blacksmith VERSION 0.0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")

set(LIBRARY_NAME bs)
set(EXECUTABLE_NAME blacksmith)

option(ENABLE_JSON "Add functionality for JSON export using nlohmann/json library." ON)
option(ENABLE_JITTING "Add functionality for jitting the hammering code using asmjit library." ON)
option(WITH_SAMSUNG_PARAMETERS "Use debugging parameters for Samsung DIMMs" OFF)

# credits to https://stackoverflow.com/a/19578320/3017719
if (NOT WIN32)
    string(ASCII 27 Esc)
    set(ColourReset "${Esc}[m")
    set(BoldRed "${Esc}[1;31m")
endif ()

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
                GIT_REPOSITORY https://github.com/ArthurSonzogni/nlohmann_json_cmake_fetchcontent
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
enable_cxx_compiler_flag_if_supported("-Wno-unused-function")
enable_cxx_compiler_flag_if_supported("-Wno-format-security")

# set default value for GIT_COMMIT_HASH preprocessor directive
set(GIT_COMMIT_HASH "NO_REPOSITORY")
execute_process(COMMAND "git" "status" RESULT_VARIABLE ret OUTPUT_QUIET)
if (ret EQUAL "0")
    # overwrite GIT_COMMIT_HASH variable
    execute_process(
            COMMAND git rev-parse HEAD
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            OUTPUT_VARIABLE GIT_COMMIT_HASH
            OUTPUT_STRIP_TRAILING_WHITESPACE)
endif ()

set(SOURCES
        src/Fuzzer/Aggressor.cpp
        src/Fuzzer/CodeJitter.cpp
        src/Memory/DRAMAddr.cpp
        src/Memory/DramAnalyzer.cpp
        src/Fuzzer/PatternBuilder.cpp
        src/Fuzzer/PatternAddressMapper.cpp
        src/Memory/Memory.cpp
        src/Fuzzer/FuzzingParameterSet.cpp
        src/Fuzzer/HammeringPattern.cpp
        src/Fuzzer/AggressorAccessPattern.cpp
        src/Fuzzer/BitFlip.cpp
        src/Utilities/Logger.cpp
        src/Utilities/Enums.cpp
        src/Forges/TraditionalHammerer.cpp
        src/Forges/FuzzyHammerer.cpp
        src/Forges/ReplayingHammerer.cpp)

set(HEADER_ONLY
        include/GlobalDefines.hpp
        include/Utilities/TimeHelper.hpp)

add_library(${LIBRARY_NAME} ${SOURCES} ${HEADER_ONLY})
target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)
if (WITH_SAMSUNG_PARAMETERS)
    message("${BoldRed}==============================================================================")
    message(">>> ATTENTION: WITH_SAMSUNG_PARAMETERS=ON. This is intended for debugging only!")
    message("==============================================================================${ColourReset}")
    target_compile_definitions(${LIBRARY_NAME} PRIVATE "-DDEBUG_SAMSUNG=1")
endif ()

if (ENABLE_JITTING)
    target_include_directories(${LIBRARY_NAME} PUBLIC ${ASMJIT_INCLUDE_DIR})
    target_link_libraries(${LIBRARY_NAME} PUBLIC asmjit)
endif ()

if (ENABLE_JSON)
    target_link_libraries(${LIBRARY_NAME} PUBLIC nlohmann_json::nlohmann_json)
endif ()

add_executable(${EXECUTABLE_NAME} src/Blacksmith.cpp include/Blacksmith.hpp)
target_link_libraries(${EXECUTABLE_NAME} PRIVATE ${LIBRARY_NAME})
target_compile_definitions(${EXECUTABLE_NAME} PRIVATE "-DGIT_COMMIT_HASH=\"${GIT_COMMIT_HASH}\"")
if (WITH_SAMSUNG_PARAMETERS)
    target_compile_definitions(${EXECUTABLE_NAME} PRIVATE "-DDEBUG_SAMSUNG=1")
endif ()

# forces CMake to delete variable's value from CMake cache: uses either the default value or the value passed as param
# e.g., cmake -DWITH_SAMSUNG_PARAMETERS=ON ..
# https://stackoverflow.com/a/53159688/3017719
unset(WITH_SAMSUNG_PARAMETERS CACHE)
