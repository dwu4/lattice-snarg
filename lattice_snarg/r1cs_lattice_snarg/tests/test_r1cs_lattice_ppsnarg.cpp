/** @file
 *****************************************************************************
 
 Test program that exercises the ppSNARG (first generator, then
 prover, then verifier) on an examples R1CS instance.

 *****************************************************************************
 * @author     Samir Menon, Brennan Shacklett, and David J. Wu
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <cassert>
#include <cstdio>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <lattice_snarg/algebra/lattice/lattice_pp.hpp>
#include <lattice_snarg/r1cs_lattice_snarg/examples/run_r1cs_lattice_ppsnarg.hpp>

using namespace libsnark;

template<typename ppT>
void test_r1cs_lattice_ppsnarg(size_t num_constraints, size_t input_size) {
    libff::print_header("(enter) Test R1CS lattice ppSNARG");

    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_field_input<libff::Fr<ppT> >(num_constraints, input_size);
    const bool res = run_r1cs_lattice_ppsnarg<ppT>(example);
    
    if (!res) {
        libff::print_header("TEST FAILED");
    }

    libff::print_header("(leave) Test R1CS lattice ppSNARG");
}

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cout << "usage: ./libsnark/test_r1cs_lattice_ppsnarg n_constraints n_inputs" << std::endl;
        return -1;
    }

    lattice_pp::init_public_params();
    libff::start_profiling();

    test_r1cs_lattice_ppsnarg<lattice_pp>(atoi(argv[1]), atoi(argv[2]));
}
