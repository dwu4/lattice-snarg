cmake_minimum_required(VERSION 2.8)

project (lattice_snarg)

if("${LIBSNARK_DIR}" STREQUAL "")
  set(
    LIBSNARK_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/libsnark"
    CACHE
    STRING
    "Optionally specify the libsnark installation directory relative to the source directory (default: inside libsnark folder)"
  )
else()
  set(LIBSNARK_DIR "${LIBSNARK_DIR}")
endif()

if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  # Common compilation flags and warning configuration
  set(
    CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra -Wfatal-errors"
  )
  if("${MULTICORE}")
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp")
  endif()
  # Default optimizations flags (to override, use -DOPT_FLAGS=...)
  if("${OPT_FLAGS}" STREQUAL "")
    set(
      OPT_FLAGS
      "-ggdb3 -O2 -march=native -mtune=native"
    )
  endif()
endif()

set(
  CMAKE_CXX_FLAGS
  "${CMAKE_CXX_FLAGS} ${OPT_FLAGS}"
)

find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARIES NAMES gmp libgmp)
find_library(NTL_LIBRARIES NAMES ntl libntl)

include_directories(.)

add_subdirectory(libsnark)
add_subdirectory(lattice_snarg)
