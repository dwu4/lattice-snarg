/** @file
 *****************************************************************************

 Implementation of functionality that runs the lattice-based R1CS ppSNARG for
 a R1CS example instance.

 See run_r1cs_lattice_ppsnarg.hpp

 *****************************************************************************
 * @author     Samir Menon, Brennan Shacklett, and David J. Wu
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef RUN_R1CS_LATTICE_PPSNARG_TCC_
#define RUN_R1CS_LATTICE_PPSNARG_TCC_

#include <sstream>
#include <type_traits>

#include <libff/common/profiling.hpp>

#include <lattice_snarg/r1cs_lattice_snarg/r1cs_lattice_ppsnarg.hpp>

namespace libsnark {

/**
 * The code below provides an example of all stages of running a R1CS ppSNARG.
 *
 * Of course, in a real-life scenario, we would have three distinct entities,
 * mangled into one in the demonstration below. The three entities are as follows.
 * (1) The "generator", which runs the ppzkSNARK generator on input a given
 *     constraint system CS to create a proving and a verification key for CS.
 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
 *     a primary input for CS, and an auxiliary input for CS.
 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
 *     a primary input for CS, and a proof.
 */
template<typename ppT>
bool run_r1cs_lattice_ppsnarg(const r1cs_example<libff::Fr<ppT> > &example) {
    libff::enter_block("Call to run_r1cs_lattice_ppsnarg");

    libff::print_header("R1CS lattice ppSNARG Generator");
    r1cs_lattice_ppsnarg_keypair<ppT> keypair = r1cs_lattice_ppsnarg_generator<ppT>(example.constraint_system);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    libff::print_header("R1CS lattice ppSNARG Prover");
    r1cs_lattice_ppsnarg_proof<ppT> proof = r1cs_lattice_ppsnarg_prover<ppT>(keypair.crs, example.primary_input, example.auxiliary_input);
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");

    libff::print_header("R1CS lattice ppSNARG Verifier");
    const bool ans = r1cs_lattice_ppsnarg_verifier<ppT>(keypair.vk, example.primary_input, proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    libff::leave_block("Call to run_r1cs_lattice_ppsnarg");

    return ans;
}

} // libsnark

#endif // RUN_R1CS_LATTICE_PPSNARG_TCC_
