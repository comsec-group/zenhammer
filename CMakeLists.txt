include(CheckCXXCompilerFlag)
cmake_minimum_required(VERSION 3.14)
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

##############################
# Check if asmjit is installed
##############################

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/Modules" ${CMAKE_MODULE_PATH})
find_package(ASMJIT)
if (NOT ASMJIT_FOUND)
    message("Trying to download and install asmjit, if this fails use this one-liner: git clone https://github.com/asmjit/asmjit && cd asmjit && cmake . && make && sudo make install && sudo ldconfig")
    message("Downloading asmjit")
    include(FetchContent)
    set(FETCHCONTENT_UPDATES_DISCONNECTED ON)
    FetchContent_Declare(
            asmjit
            GIT_REPOSITORY https://github.com/asmjit/asmjit.git)
    FetchContent_Populate(asmjit)
endif ()

##############################
# Download and install nlohmann-json if required
##############################

find_package(nlohmann_json QUIET)
if (NOT nlohmann_json_FOUND)
    message("Downloading nlohmann_json")
    include(FetchContent)
    set(JSON_BuildTests OFF CACHE INTERNAL "")
    set(FETCHCONTENT_UPDATES_DISCONNECTED ON)
    FetchContent_Declare(
            nlohmann_json
            GIT_REPOSITORY https://github.com/nlohmann/json.git
            GIT_TAG v3.7.3)
    FetchContent_MakeAvailable(nlohmann_json)
endif ()


set(SOURCES
        src/Fuzzer/Aggressor.cpp
        src/Fuzzer/CodeJitter.cpp
        src/DRAMAddr.cpp
        src/DramAnalyzer.cpp
        src/Fuzzer/PatternBuilder.cpp
        src/PatternAddressMapping.cpp
        src/Memory.cpp
        src/Fuzzer/FuzzingParameterSet.cpp
        src/Fuzzer/HammeringPattern.cpp
        src/Fuzzer/AggressorAccessPattern.cpp
        src/Fuzzer/BitFlip.cpp)

set(HEADER_ONLY
        include/Utilities/ISerializable.hpp
        include/Fuzzer/PatternAddressMapping.hpp)

set(LIBRARY_NAME libblacksmith)
add_library(${LIBRARY_NAME} ${SOURCES} ${HEADER_ONLY})
target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(${LIBRARY_NAME} PUBLIC asmjit)
target_link_libraries(${LIBRARY_NAME} PUBLIC nlohmann_json::nlohmann_json)

add_executable(blacksmith src/Blacksmith.cpp include/Blacksmith.hpp)
target_link_libraries(blacksmith PRIVATE ${LIBRARY_NAME})

