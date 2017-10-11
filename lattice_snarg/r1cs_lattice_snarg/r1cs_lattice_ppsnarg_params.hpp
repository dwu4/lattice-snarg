/** @file
 *****************************************************************************

 Declaration of public-parameter selectors for the lattice-based R1CS ppSNARG.

 *****************************************************************************
 * @author     Samir Menon, Brennan Shacklett, and David J. Wu
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef R1CS_LATTICE_PPSNARG_PARAMS_HPP_
#define R1CS_LATTICE_PPSNARG_PARAMS_HPP_

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

namespace libsnark {

/**
 * Below are various template aliases (used for convenience).
 */

template<typename ppT>
using r1cs_lattice_ppsnarg_constraint_system = r1cs_constraint_system<libff::Fr<ppT> >;

template<typename ppT>
using r1cs_lattice_ppsnarg_primary_input = r1cs_primary_input<libff::Fr<ppT> >;

template<typename ppT>
using r1cs_lattice_ppsnarg_auxiliary_input = r1cs_auxiliary_input<libff::Fr<ppT> >;

} // libsnark

#endif // R1CS_LATTICE_PPSNARG_PARAMS_HPP_
