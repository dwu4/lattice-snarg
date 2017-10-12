/** @file
 *****************************************************************************

 Sample parameters for the lattice-based vector encryption scheme for the
 lattice-based R1CS ppSNARG. The LWE parameters are chosen to provide 80-bits
 of security, and correctness error 2^{-40} for verifying QAPs with degree up
 to 10000 (over a finite field of size ~10000). Parameter selection based on
 the security analysis in [LP10].

 The plaintext dimension is chosen based on the number of queries needed to
 acheive soundness error 2^{-40} for the QAP-based linear PCP for verifying
 R1CS systems with up to 10000 constraints (and a field of size ~10000).

 References:

  [LP10]: Richard Lindner and Chris Peikert. Better Key Sizes (and Attacks) for
          LWE-Based Encryption. In CT-RSA, 2011.

 *****************************************************************************
 * @author     Samir Menon, Brennan Shacklett, and David J. Wu
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef LWE_PARAM_HPP_
#define LWE_PARAM_HPP_

#include <math.h>
#include <stdint.h>
#include <NTL/ZZ.h>

namespace LWE {

// Lattice dimension (parameters chosen to ensure 80-bits of security)
const uint32_t n = 1455;

// Noise distribution standard deviation
const double stddev = 6.0;

// 15 queries (~ 2^-40 soundness error for circuits of size < 10000)
const uint32_t l = 15;
const uint32_t pt_dim = l*4;

// Plaintext modulus
const uint64_t p_int = 65537;
const NTL::ZZ p(p_int);

// Ciphertext modulus
const NTL::ZZ q(1ul << 58);
}

#endif // LWE_PARAM_HPP_
