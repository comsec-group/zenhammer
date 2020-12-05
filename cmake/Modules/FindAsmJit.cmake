# - Find AsmJit
# Complete x86/x64 JIT and Remote Assembler for C++
# https://github.com/kobalicek/asmjit
#
# The module defines the following variables:
#  ASMJIT_FOUND - the system has asmjit
#  ASMJIT_INCLUDE_DIR - where to find asmjit.h
#  ASMJIT_INCLUDE_DIRS - asmjit includes
#  ASMJIT_LIBRARY - where to find the asmjit library
#  ASMJIT_LIBRARIES - additional libraries
#  ASMJIT_ROOT_DIR - root dir (ex. /usr/local)

# set ASMJIT_INCLUDE_DIR
find_path(ASMJIT_INCLUDE_DIR
        NAMES
        asmjit.h
        PATH_SUFFIX
        asmjit
        DOC
        "AsmJit include directory"
        )

# set ASMJIT_INCLUDE_DIRS
set(ASMJIT_INCLUDE_DIRS ${ASMJIT_INCLUDE_DIR})

# set ASMJIT_LIBRARY
find_library(ASMJIT_LIBRARY
        NAMES
        asmjit
        DOC
        "AsmJit library location"
        )

# set ASMJIT_LIBRARIES
set(ASMJIT_LIBRARIES ${ASMJIT_LIBRARY})

# root dir
# try to guess root dir from include dir
if (ASMJIT_INCLUDE_DIR)
    string(REGEX REPLACE "(.*)/include.*" "\\1" ASMJIT_ROOT_DIR ${ASMJIT_INCLUDE_DIR})

    # try to guess root dir from library dir
elseif (ASMJIT_LIBRARY)
    string(REGEX REPLACE "(.*)/lib[/|32|64].*" "\\1" ASMJIT_ROOT_DIR ${ASMJIT_LIBRARY})
endif ()

# handle REQUIRED and QUIET options
include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(AsmJit DEFAULT_MSG ASMJIT_LIBRARY
        ASMJIT_INCLUDE_DIR
        ASMJIT_INCLUDE_DIRS
        ASMJIT_LIBRARIES
        ASMJIT_ROOT_DIR
        )

mark_as_advanced(
        ASMJIT_LIBRARY
        ASMJIT_LIBRARIES
        ASMJIT_INCLUDE_DIR
        ASMJIT_INCLUDE_DIRS
        ASMJIT_ROOT_DIR
        ASMJIT_INTERFACE_VERSION
)
