/** @file
 *****************************************************************************

 Declaration of functionality that runs the lattice-based R1CS ppSNARG for
 a R1CS example instance.

 *****************************************************************************
 * @author     Samir Menon, Brennan Shacklett, and David J. Wu
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef RUN_R1CS_LATTICE_PPSNARG_HPP_
#define RUN_R1CS_LATTICE_PPSNARG_HPP_

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>

namespace libsnark {

/**
 * Runs the ppSNARG (generator, prover, and verifier) for a given
 * R1CS example (specified by a constraint system, input, and witness).
 */
template<typename ppT>
bool run_r1cs_lattice_ppsnarg(const r1cs_example<libff::Fr<ppT> > &example);

} // libsnark

#include <lattice_snarg/r1cs_lattice_snarg/examples/run_r1cs_lattice_ppsnarg.tcc>

#endif // RUN_R1CS_LATTICE_PPSNARG_HPP_
