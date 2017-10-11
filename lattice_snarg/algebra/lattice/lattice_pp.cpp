/** @file
 *****************************************************************************

 Description of finite field for the lattice-based SNARG.

 *****************************************************************************
 * @author     Samir Menon, Brennan Shacklett, and David J. Wu
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include "lattice_pp.hpp"
#include "lwe_params.hpp"

namespace libsnark {

void lattice_pp::init_public_params() {
  Fp_type::s = 16; // log2(modulus) OR modulus = 2^s * t + 1
  Fp_type::t = 1;  // with t odd
  Fp_type::multiplicative_generator = Fp_type(3); // generator of Fp^*
  Fp_type::root_of_unity = Fp_type::multiplicative_generator^Fp_type::t; // generator^((modulus-1)/2^s)m
}

}
