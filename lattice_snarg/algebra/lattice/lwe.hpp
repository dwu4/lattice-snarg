/** @file
 *****************************************************************************

 Declaration of interfaces for a secret-key lattice-based additively homomorphic
 vector encryption scheme.

 This includes:
 - class for secret key
 - class for ciphertext
 - key generation algorithm
 - encryption algorithm
 - decryption algorithm
 - operations for homomorphic addition and scalar multiplication of ciphertexts

 The implementation instantiates (a modification of) the LWE-based cryptosystem
 from [LP10] (described in [Pei16, Section 5.2.3]). The implementation encodes
 the message in the low-order bits of the ciphertext.

 References:

  [LP10]: Richard Lindner and Chris Peikert. Better Key Sizes (and Attacks) for
          LWE-Based Encryption. In CT-RSA, 2011.

  [Pei16]: Chris Peikert. A Decade of Lattice Cryptography. Available as
           Report 2015/939 on IACR Cryptology ePrint Archive 
           (https://eprint.iacr.org/2015/939.pdf).

 *****************************************************************************
 * @author     Samir Menon, Brennan Shacklett, and David J. Wu
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef LWE_HPP_
#define LWE_HPP_

#include <NTL/mat_ZZ_p.h>
#include <random>
#include "lwe_params.hpp"

namespace LWE {

using matrix = NTL::mat_ZZ_p;
using vector = NTL::vec_ZZ_p;
using plaintext = vector;

class secret_key {
public:
    matrix A {NTL::INIT_SIZE, n + pt_dim, n};
    matrix S {NTL::INIT_SIZE, n + pt_dim, pt_dim};
};

class ciphertext {
public:
  // Assignment operator
  ciphertext& operator=(const ciphertext& other);

  // Homomorphic addition
  ciphertext operator+(const ciphertext &other) const;
  ciphertext& operator+=(const ciphertext &other);

  // Homomorphic scalar multiplication
  ciphertext operator*(uint64_t val) const;
  ciphertext operator*(const NTL::ZZ_p &val) const;
  ciphertext& operator*=(uint64_t val);
  ciphertext& operator*=(const NTL::ZZ_p &val);

private:
  vector ctxt;

friend ciphertext encrypt(const secret_key &sk, const plaintext &pt);
friend plaintext  decrypt(const secret_key &sk, const ciphertext &ct);
};

secret_key keygen();
ciphertext encrypt(const secret_key &sk, const plaintext &pt);
plaintext  decrypt(const secret_key &sk, const ciphertext &ct);

ciphertext operator*(uint64_t val, const ciphertext& ct);
ciphertext operator*(const NTL::ZZ_p &val, const ciphertext& ct);

}

#endif // LWE_HPP_
