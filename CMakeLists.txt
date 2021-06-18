include(CheckCXXCompilerFlag)

cmake_minimum_required(VERSION 3.14)
project(blacksmith VERSION 0.0.1 LANGUAGES CXX)

# required for the initialization of the DRAMAddr::Configs map
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -Werror")
#set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -pedantic -Werror")

set(LIBRARY_NAME bs)
set(EXECUTABLE_NAME blacksmith)
set(ROOT_DEPENDENCIES deps)

SET(OPT_ENABLE_JSON ON BOOL FORCE "Add functionality for JSON export using nlohmann/json library.")
SET(OPT_ENABLE_JITTING ON BOOL FORCE "Add functionality for jitting the hammering code using asmjit library.")
SET(WITH_SAMSUNG_PARAMETERS OFF BOOL FORCE "Use debugging parameters for Samsung DIMMs.")
SET(WITH_DIMM10_PARAMETERS OFF BOOL FORCE "Use debugging parameters for DIMM 10, Hynix.")

# credits to https://stackoverflow.com/a/19578320/3017719
if (NOT WIN32)
    string(ASCII 27 Esc)
    set(ColourReset "${Esc}[m")
    set(BoldRed "${Esc}[1;31m")
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
execute_process(COMMAND "git" "status" RESULT_VARIABLE ret OUTPUT_QUIET ERROR_QUIET)
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

add_executable(${EXECUTABLE_NAME} src/Blacksmith.cpp include/Blacksmith.hpp)
target_link_libraries(${EXECUTABLE_NAME} PRIVATE ${LIBRARY_NAME})

if (WITH_SAMSUNG_PARAMETERS MATCHES ON)
    message("${BoldRed}==============================================================================")
    message(">>> ATTENTION: WITH_SAMSUNG_PARAMETERS=ON. This is intended for debugging only!")
    message("==============================================================================${ColourReset}")
    target_compile_definitions(${LIBRARY_NAME} PRIVATE "-DDEBUG_SAMSUNG=1")
    target_compile_definitions(${EXECUTABLE_NAME} PRIVATE "-DDEBUG_SAMSUNG=1")
endif()
if (WITH_DIMM10_PARAMETERS MATCHES ON)
    message("${BoldRed}==============================================================================")
    message(">>> ATTENTION: WITH_DIMM10_PARAMETERS=ON. This is intended for debugging only!")
    message("==============================================================================${ColourReset}")
    target_compile_definitions(${LIBRARY_NAME} PRIVATE "-DDEBUG_DIMM10=1")
    target_compile_definitions(${EXECUTABLE_NAME} PRIVATE "-DDEBUG_DIMM10=1")
endif()


if (OPT_ENABLE_JITTING MATCHES ON)
    add_subdirectory(${ROOT_DEPENDENCIES}/asmjit)
    target_compile_definitions(${LIBRARY_NAME} PRIVATE "-DENABLE_JITTING")
    target_link_libraries(${LIBRARY_NAME} PUBLIC asmjit)
    target_compile_definitions(${EXECUTABLE_NAME} PRIVATE "-DENABLE_JITTING=1")
endif ()

if (OPT_ENABLE_JSON MATCHES ON)
    add_subdirectory(${ROOT_DEPENDENCIES}/json)
    target_compile_definitions(${LIBRARY_NAME} PRIVATE "-DENABLE_JSON")
    target_link_libraries(${LIBRARY_NAME} PUBLIC nlohmann_json::nlohmann_json)
    target_compile_definitions(${EXECUTABLE_NAME} PRIVATE "-DENABLE_JSON")
endif ()

target_compile_definitions(${EXECUTABLE_NAME} PRIVATE "-DGIT_COMMIT_HASH=\"${GIT_COMMIT_HASH}\"")

# forces CMake to delete variable's value from CMake cache: uses either the default value or the value passed as param
# e.g., cmake -DWITH_SAMSUNG_PARAMETERS=ON ..
# https://stackoverflow.com/a/53159688/3017719
unset(WITH_SAMSUNG_PARAMETERS)
unset(WITH_DIMM10_PARAMETERS)
unset(OPT_ENABLE_JSON)
unset(OPT_ENABLE_JITTING)
