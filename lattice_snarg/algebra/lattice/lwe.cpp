/** @file
*****************************************************************************

Implementation of a secret-key lattice-based additively homomorphic
vector encryption scheme.

See lwe.hpp

*****************************************************************************
* @author     Samir Menon, Brennan Shacklett, and David J. Wu
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#include <cstdlib>
#include <iostream>
#include <cassert>
#include <random>
#include <cstdint>
#include <fstream>
#include <NTL/ZZ.h>

#include "lwe.hpp"
#include <libsnark/common/libsnark_serialization.hpp>

using namespace std;
namespace LWE {

static NTL::ZZ_p random(const NTL::ZZ &mod) {
    // Choose a random value from a space that is 128-bits
    // longer than the target space, and then round down.

    long num_bytes = NTL::NumBytes(mod) + 16;
    unsigned char bytes[num_bytes];
    static ifstream urandom("/dev/urandom", ios::binary);
    urandom.read(reinterpret_cast<char *>(bytes), num_bytes);

    NTL::ZZ randZZ = NTL::ZZFromBytes(bytes, num_bytes);

    return NTL::to_ZZ_p(randZZ % mod);
}

// Sample a discrete Gaussian variable using the Box-Muller
// transform.
static int32_t sample_discrete_gaussian(double stddev) {
    static const double PI = 4.0*atan(1.0);

    double r1 = ((double) rand()) / RAND_MAX;
    double r2 = ((double) rand()) / RAND_MAX;
    double theta = 2*PI*r1;

    return (int32_t) floor(stddev * sqrt(-2.0*log(r2)) * cos(theta) + 0.5);
}

ciphertext& ciphertext::operator=(const ciphertext& other) {
    NTL::ZZ_p::init(LWE::q);

    this->ctxt = other.ctxt;

    return *this;
}

ciphertext ciphertext::operator+(const ciphertext &other) const {
    ciphertext sum = *this;
    sum += other;

    return sum;
}

ciphertext& ciphertext::operator+=(const ciphertext &other) {
    NTL::ZZ_p::init(LWE::q);

    this->ctxt += other.ctxt;
    return *this;
}

ciphertext ciphertext::operator*(uint64_t val) const {
    return operator*(NTL::ZZ_p(val));
}

ciphertext ciphertext::operator*(const NTL::ZZ_p &val) const {
    ciphertext prod = *this;
    prod *= val;

    return prod;
}

ciphertext& ciphertext::operator*=(uint64_t val) {
    return operator*=(NTL::ZZ_p(val));
}

ciphertext& ciphertext::operator*=(const NTL::ZZ_p &val) {
    NTL::ZZ_p::init(LWE::q);

    this->ctxt *= val;
    return *this;
}

ciphertext operator*(uint64_t val, const ciphertext& ct) {
    return operator*(NTL::ZZ_p(val), ct);
}

ciphertext operator*(const NTL::ZZ_p &val, const ciphertext& ct) {
    ciphertext prod = ct;
    prod *= val;

    return prod;
}

secret_key keygen() {
    NTL::ZZ_p::init(LWE::q);
    secret_key sk;

    // Sampled uniformly random matrix A
    matrix A_hat(NTL::INIT_SIZE, n, n);
    for (size_t i = 1; i <= n; i++) {
        for (size_t j = 1; j <= n; j++) {
            A_hat(i, j) = random(q);
        }
    }

    // Sample secret keys from error distribution
    matrix S_hat(NTL::INIT_SIZE, n, pt_dim);
    for (size_t i = 1; i <= n; i++) {
        for (size_t j = 1; j <= pt_dim; j++) {
            S_hat(i, j) = sample_discrete_gaussian(stddev);
        }
    }

    // Sample errors from error distribution
    matrix E_hat(NTL::INIT_SIZE, pt_dim, n);
    for (size_t i = 1; i <= pt_dim; i++) {
        for (size_t j = 1; j <= n; j++) {
            E_hat(i, j) = sample_discrete_gaussian(stddev);
        }
    }

    // Construct A = [ A_hat ; S_hat^T * A_hat + p * E_hat ]
    matrix A_bottom = NTL::transpose(S_hat)*A_hat + p_int*E_hat;

    for (size_t i = 1; i <= n; i++) {
        for (size_t j = 1; j <= n; j++) {
            sk.A(i, j) = A_hat(i, j);
        }
    }

    for (size_t i = 1; i <= pt_dim; i++) {
        for (size_t j = 1; j <= n; j++) {
            sk.A(i + n, j) = A_bottom(i, j);
        }
    }

    // Construct S = [ -S_hat ; I ]
    for (size_t i = 1; i <= n; i++) {
        for (size_t j = 1; j <= pt_dim; j++) {
            sk.S(i, j) = -S_hat(i, j);
        }
    }

    matrix ident = NTL::ident_mat_ZZ_p(pt_dim);
    for (size_t i = 1; i <= pt_dim; i++) {
        for (size_t j = 1; j <= pt_dim; j++) {
            sk.S(i + n, j) = ident(i, j);
        }
    }

    return sk;
}

ciphertext encrypt(const secret_key &sk, const plaintext &pt) {
    NTL::ZZ_p::init(LWE::q);

    // Sample an LWE error vector for the randomness (n x 1)
    vector r(NTL::INIT_SIZE, n);
    for (size_t i = 1; i <= n; i++) {
        r(i) = sample_discrete_gaussian(stddev);  
    }

    vector v_padded(NTL::INIT_SIZE, n + pt_dim);
    for (size_t i = 1; i <= n; i++) {
        v_padded(i) = 0;
    }

    for (size_t i = 1; i <= pt_dim; i++) {
        v_padded(i + n) = pt(i);
    }

    ciphertext ctxt;
    ctxt.ctxt = sk.A*r + v_padded;

    // Add error to each component of ciphertext
    for (size_t i = 1; i <= n + pt_dim; i++) {
        ctxt.ctxt(i) += sample_discrete_gaussian(stddev) * LWE::p_int;
    }

    return ctxt;
}

plaintext decrypt(const secret_key &sk, const ciphertext& ct) {
    NTL::ZZ_p::init(LWE::q);
    vector modqvec = NTL::transpose(sk.S)*ct.ctxt;

    NTL::ZZ_p::init(LWE::p);
    plaintext pt(NTL::INIT_SIZE, pt_dim);
    for (size_t i = 1; i <= pt_dim; i++) {
        NTL::ZZ modq = NTL::rep(modqvec(i));
        if (modq > q/2) {
            modq -= q;
        } else if (modq < -q/2) {
            modq += q;
        }
        pt(i) = ((modq % p_int) + p_int) % p_int;
    }

    return pt;
}

}
