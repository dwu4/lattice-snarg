add_library(
  lattice_snarg
  STATIC

  algebra/lattice/lattice_pp.cpp
  algebra/lattice/lwe.cpp
)

target_link_libraries(
  lattice_snarg

  snark
  ${NTL_LIBRARIES}
  ${GMP_LIBRARIES}
)

target_include_directories(
  lattice_snarg

  PUBLIC
  ${LIBSNARK_DIR}
)

add_executable(
  r1cs_lattice_snarg_test

  r1cs_lattice_snarg/tests/test_r1cs_lattice_ppsnarg.cpp
)
target_link_libraries(
  r1cs_lattice_snarg_test

  lattice_snarg
)

add_executable(
  lattice_test

  algebra/lattice/tests/test_lattice.cpp
)
target_link_libraries(
  lattice_test

  lattice_snarg
)
