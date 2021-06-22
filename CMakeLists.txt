cmake_minimum_required(VERSION 3.11 FATAL_ERROR)
project(blacksmith VERSION 0.0.1 LANGUAGES CXX)

# === DEFINITIONS =============================================================

set(GIT_COMMIT_HASH "NO_REPOSITORY")

execute_process(
        COMMAND git status
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
        libblacksmith
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
        libblacksmith
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(
        libblacksmith
        PRIVATE
        asmjit
        PUBLIC
        nlohmann_json::nlohmann_json
)

# Note: PUBLIC to also force consumers (i.e., the blacksmith executable) to use
# these features and options.
target_compile_features(libblacksmith PUBLIC cxx_std_20)

target_compile_options(
        libblacksmith
        PUBLIC
        -O0
        -Wall
        -Wextra
        -Wno-unused-function
        -Wno-format-security
)

target_compile_definitions(
        libblacksmith
        PUBLIC
        ENABLE_JSON
)

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
        libblacksmith
        nlohmann_json::nlohmann_json
)

target_include_directories(
        blacksmith
        PRIVATE
        libblacksmith
        argagg
)
