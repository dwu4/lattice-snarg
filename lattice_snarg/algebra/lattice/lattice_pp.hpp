/** @file
 *****************************************************************************

 Description of finite field for the lattice-based SNARG.

 *****************************************************************************
 * @author     Samir Menon, Brennan Shacklett, and David J. Wu
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <lattice_snarg/algebra/fields/ntlfp.hpp>
#include <libff/algebra/curves/public_params.hpp>
#include "lwe_params.hpp"

#ifndef LATTICE_PP_HPP_
#define LATTICE_PP_HPP_

namespace libsnark {

class lattice_pp {
  private:
    static const unsigned long lattice_modulus;
  public:
    
    using Fp_type = NTLFp_model<LWE::p_int>;

    static void init_public_params();
};

}

#endif // LATTICE_PP_HPP_
