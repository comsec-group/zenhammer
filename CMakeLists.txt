cmake_minimum_required(VERSION 3.11 FATAL_ERROR)
project(blacksmith VERSION 0.0.1 LANGUAGES CXX)

# === OPTIONS ==================================================================

set(
        BLACKSMITH_ENABLE_JSON
        ON
        CACHE BOOL
        "Use the nlohmann/json library to export JSON-formatted fuzzing data."
        FORCE
)

set(
        BLACKSMITH_ENABLE_JITTING
        ON
        CACHE BOOL
        "Use the asmjit library to jit the hammering code."
        FORCE
)

# TODO: sanitize before release!
set(
        BLACKSMITH_USE_SAMSUNG_PARAMS
        OFF
        CACHE BOOL
        "Use debugging parameters specific to Samsung DIMMs."
        FORCE
)

# TODO: sanitize before release!
set(
        BLACKSMITH_USE_DIMM_10_PARAMS
        OFF
        CACHE BOOL
        "Use debugging parameters specific to DIMM 10 (Hyinx)."
        FORCE
)

string(ASCII 27 ESC)

# === DEFINITIONS ==============================================================

set(GIT_COMMIT_HASH "NO_REPOSITORY")

execute_process(
        COMMAND git status
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        RESULT_VARIABLE ret
        OUTPUT_QUIET
        ERROR_QUIET
)

if (ret EQUAL "0")
    # We're in a git repository, attempt to retrieve the current commit tag.
    execute_process(
            COMMAND git rev-parse HEAD
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            OUTPUT_VARIABLE GIT_COMMIT_HASH
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif ()

# === DEPENDENCIES =============================================================

add_subdirectory(external)

# === LIBBLACKSMITH ============================================================

add_library(
        bs
        include/GlobalDefines.hpp
        include/Utilities/TimeHelper.hpp
        src/Forges/FuzzyHammerer.cpp
        src/Forges/ReplayingHammerer.cpp
        src/Forges/TraditionalHammerer.cpp
        src/Fuzzer/Aggressor.cpp
        src/Fuzzer/AggressorAccessPattern.cpp
        src/Fuzzer/BitFlip.cpp
        src/Fuzzer/CodeJitter.cpp
        src/Fuzzer/FuzzingParameterSet.cpp
        src/Fuzzer/HammeringPattern.cpp
        src/Fuzzer/PatternAddressMapper.cpp
        src/Fuzzer/PatternBuilder.cpp
        src/Memory/DRAMAddr.cpp
        src/Memory/DramAnalyzer.cpp
        src/Memory/Memory.cpp
        src/Utilities/Enums.cpp
        src/Utilities/Logger.cpp
)

target_include_directories(
        bs
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Note: PUBLIC to also force consumers (i.e., the blacksmith executable) to use
# these features and options.
target_compile_features(
        bs
        PUBLIC
        cxx_std_17
)

target_compile_options(
        bs
        PUBLIC
        -O0
        -Wall
        -Wextra
        -Wno-unused-function
        -Wno-format-security
)

if (BLACKSMITH_ENABLE_JSON)
    target_link_libraries(
            bs
            PUBLIC
            nlohmann_json::nlohmann_json
    )

    target_compile_definitions(
            bs
            PUBLIC
            ENABLE_JSON
    )
endif ()

if (BLACKSMITH_ENABLE_JITTING)
    target_link_libraries(
            bs
            PRIVATE
            asmjit
    )

    target_compile_definitions(
            bs
            PUBLIC
            ENABLE_JITTING
    )
endif ()

# TODO: sanitize before release!
if (BLACKSMITH_USE_SAMSUNG_PARAMS)
    message("\n${ESC}[7;31m==================================== >> ${ESC}[5mWARNING!${ESC}[m${ESC}[7;31m << ====================================${ESC}[m")
    message("${ESC}[7;31m=${ESC}[m${ESC}[31m ATTENTION: BLACKSMITH_USE_SAMSUNG_PARAMS is ON. This is intended for debugging only! ${ESC}[7;31m=${ESC}[m")
    message("${ESC}[7;31m==================================== >> ${ESC}[5mWARNING!${ESC}[m${ESC}[7;31m << ====================================${ESC}[m\n")
    target_compile_definitions(
            bs
            PUBLIC
            DEBUG_SAMSUNG
    )
endif ()

if (BLACKSMITH_USE_DIMM_10_PARAMS)
    message("\n${ESC}[7;31m==================================== >> ${ESC}[5mWARNING!${ESC}[m${ESC}[7;31m << ====================================${ESC}[m")
    message("${ESC}[7;31m=${ESC}[m${ESC}[31m ATTENTION: BLACKSMITH_USE_DIMM_10_PARAMS is ON. This is intended for debugging only! ${ESC}[7;31m=${ESC}[m")
    message("${ESC}[7;31m==================================== >> ${ESC}[5mWARNING!${ESC}[m${ESC}[7;31m << ====================================${ESC}[m\n")
    target_compile_definitions(
            bs
            PUBLIC
            DEBUG_DIMM10
    )
endif ()

# === BLACKSMITH ===============================================================

add_executable(
        blacksmith
        include/Blacksmith.hpp
        src/Blacksmith.cpp
)

target_compile_definitions(
        blacksmith
        PRIVATE
        GIT_COMMIT_HASH="${GIT_COMMIT_HASH}"
)

target_link_libraries(
        blacksmith
        PRIVATE
        bs
        argagg
)

# === CLEANUP ==================================================================

unset(BLACKSMITH_ENABLE_JSON CACHE)
unset(BLACKSMITH_ENABLE_JITTING CACHE)
unset(BLACKSMITH_USE_SAMSUNG_PARAMS CACHE)
unset(BLACKSMITH_USE_DIMM_10_PARAMS CACHE)
