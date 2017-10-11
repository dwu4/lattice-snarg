/** @file
*****************************************************************************

Implementation of interfaces for a lattice-based ppSNARG for R1CS.

See r1cs_lattice_ppsnarg.hpp

*****************************************************************************
* @author     Samir Menon, Brennan Shacklett, and David J. Wu
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#ifndef R1CS_LATTICE_PPSNARG_TCC_
#define R1CS_LATTICE_PPSNARG_TCC_

#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <sstream>
#include <inttypes.h>
#include <NTL/mat_ZZ_p.h>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <lattice_snarg/algebra/lattice/lwe.hpp>
#include <libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>

namespace libsnark {

template<typename ppT>
static LWE::matrix generate_Y(const int dim) {
    NTL::ZZ_p::init(LWE::p);
    LWE::matrix Y(NTL::INIT_SIZE, dim, dim);

    for (int i = 1; i <= dim; i++) {
        for (int j = 1; j <= dim; j++) {
            Y(i, j) = libff::Fr<ppT>::random_element().as_ZZ_p();
        }
    }

    return Y;
}

template<typename ppT>
static LWE::matrix make_query_matrix(const std::vector<libff::Fr_vector<ppT>> &A_query,
                                     const std::vector<libff::Fr_vector<ppT>> &B_query,
                                     const std::vector<libff::Fr_vector<ppT>> &C_query,
                                     const std::vector<libff::Fr_vector<ppT>> &H_query,
                                     const libff::Fr_vector<ppT> &Zs, size_t num_inputs) {
    // Strip out the first (num_inputs + 1) components of A, B, C
    // (corresponds to constant term and the bits of the statement)
    int ABC_rows = A_query[0].size() - num_inputs - 1;
    int rows = ABC_rows + 3 + H_query[0].size();
    int cols = LWE::l;

    NTL::ZZ_p::init(LWE::p);
    LWE::matrix mat(NTL::INIT_SIZE, rows, 4*cols);
    NTL::clear(mat);

    /* Creates the following matrix:
     * A|B|C 0
     *   0   H
     */

    // Copy A, B, C
    for (int i = 1; i <= ABC_rows; i++) {
        for (int j = 1; j <= cols; j++) {
            mat(i, j)          = A_query[j - 1][i - 1 + num_inputs + 1].as_ZZ_p();
            mat(i, j + cols)   = B_query[j - 1][i - 1 + num_inputs + 1].as_ZZ_p();
            mat(i, j + 2*cols) = C_query[j - 1][i - 1 + num_inputs + 1].as_ZZ_p();
        }
    }
    
    // Copy Zs to the bottom of A, B and C
    for (int i = 1; i <= 3; i++) {
        for (int j = 1; j <= cols; j++) {
            mat(ABC_rows + i, j + (i - 1)*cols) = Zs[j - 1].as_ZZ_p();
        }
    }

    // Copy H
    for (unsigned i = 1; i <= H_query[0].size(); i++) {
        for (int j = 1; j <= cols; j++) {
            mat(i + ABC_rows + 3, j + 3*cols) = H_query[j - 1][i - 1].as_ZZ_p();
        }
    }

    return mat;
}

static void encrypt_queries(std::vector<LWE::ciphertext> &enc_queries, 
                     const LWE::secret_key &sk, const LWE::matrix &queries) {
    int nrows = queries.NumRows();

    enc_queries.resize(nrows);
    for (int i = 0; i < nrows; i++) {
        enc_queries[i] = LWE::encrypt(sk, queries[i]);
    }
}

template <typename ppT>
r1cs_lattice_ppsnarg_keypair<ppT> r1cs_lattice_ppsnarg_generator(const r1cs_lattice_ppsnarg_constraint_system<ppT> &cs) {
    libff::enter_block("Call to r1cs_lattice_ppsnarg_generator");

    std::vector<libff::Fr_vector<ppT>> A_queries(r1cs_lattice_ppsnarg_num_queries);
    std::vector<libff::Fr_vector<ppT>> B_queries(r1cs_lattice_ppsnarg_num_queries);
    std::vector<libff::Fr_vector<ppT>> C_queries(r1cs_lattice_ppsnarg_num_queries);
    std::vector<libff::Fr_vector<ppT>> H_queries(r1cs_lattice_ppsnarg_num_queries);

    libff::Fr_vector<ppT> Zs;

    // The first (num_inputs + 1) components of the A, B, and C queries. These
    // components are part of the verification state.
    std::vector<libff::Fr_vector<ppT>> A_prefix(r1cs_lattice_ppsnarg_num_queries);
    std::vector<libff::Fr_vector<ppT>> B_prefix(r1cs_lattice_ppsnarg_num_queries);
    std::vector<libff::Fr_vector<ppT>> C_prefix(r1cs_lattice_ppsnarg_num_queries);

    libff::enter_block("Generate (packed) QAP queries");
    size_t num_inputs = 0;
    for (size_t i = 0; i < r1cs_lattice_ppsnarg_num_queries; i++) {
        // Draw random field element for this query
        const libff::Fr<ppT> t = libff::Fr<ppT>::random_element();

        qap_instance_evaluation<libff::Fr<ppT> > qap_inst = r1cs_to_qap_instance_map_with_evaluation(cs, t);

        if (i == 0) {
            libff::print_indent(); printf("* QAP number of variables: %zu\n", qap_inst.num_variables());
            libff::print_indent(); printf("* QAP pre degree: %zu\n", cs.constraints.size());
            libff::print_indent(); printf("* QAP degree: %zu\n", qap_inst.degree());
            libff::print_indent(); printf("* QAP number of input variables: %zu\n", qap_inst.num_inputs());

            num_inputs = qap_inst.num_inputs();
        }

        A_queries[i] = std::move(qap_inst.At); 
        B_queries[i] = std::move(qap_inst.Bt); 
        C_queries[i] = std::move(qap_inst.Ct); 
        H_queries[i] = std::move(qap_inst.Ht);

        Zs.emplace_back(qap_inst.Zt);

        for (size_t j = 0; j < num_inputs + 1; j++) {
            A_prefix[i].emplace_back(A_queries[i][j]);
            B_prefix[i].emplace_back(B_queries[i][j]);
            C_prefix[i].emplace_back(C_queries[i][j]);
        }
    }

    LWE::matrix query_mat = make_query_matrix<ppT>(A_queries, B_queries, C_queries, H_queries, Zs, num_inputs);
    libff::leave_block("Generate (packed) QAP queries");

    libff::enter_block("Apply random linear shift to packed queries");
    LWE::matrix Y = generate_Y<ppT>(4*LWE::l);
    query_mat *= Y;
    libff::leave_block("Apply random linear shift to packed queries");

    libff::enter_block("Generate verification key");
    LWE::secret_key sk = LWE::keygen();
    NTL::ZZ_p::init(NTL::ZZ(LWE::p));
    LWE::matrix Yprime = NTL::inv(NTL::transpose(Y));
    libff::leave_block("Generate verification key");
   
    libff::enter_block("Generate CRS");
    std::vector<LWE::ciphertext> enc_queries;
    encrypt_queries(enc_queries, sk, query_mat);
    libff::leave_block("Generate CRS");

    libff::leave_block("Call to r1cs_lattice_ppsnarg_generator");

    r1cs_lattice_ppsnarg_verification_key<ppT> vk = r1cs_lattice_ppsnarg_verification_key<ppT>(std::move(sk),
                                                                                                   std::move(Zs),
                                                                                                   std::move(Yprime),
                                                                                                   std::move(A_prefix),
                                                                                                   std::move(B_prefix),
                                                                                                   std::move(C_prefix));


    r1cs_lattice_ppsnarg_crs<ppT> crs = r1cs_lattice_ppsnarg_crs<ppT>(std::move(enc_queries), cs);

    return r1cs_lattice_ppsnarg_keypair<ppT>(std::move(crs), std::move(vk));
}

template <typename ppT>
r1cs_lattice_ppsnarg_proof<ppT> r1cs_lattice_ppsnarg_prover(const r1cs_lattice_ppsnarg_crs<ppT> &crs,
                                                const r1cs_lattice_ppsnarg_primary_input<ppT> &primary_input,
                                                const r1cs_lattice_ppsnarg_auxiliary_input<ppT> &auxiliary_input) {
    libff::enter_block("Call to r1cs_lattice_ppsnarg_prover");

#ifdef DEBUG
    assert(crs.constraint_system.is_satisfied(primary_input, auxiliary_input));
#endif

    const libff::Fr<ppT> d1 = libff::Fr<ppT>::random_element(),
                         d2 = libff::Fr<ppT>::random_element(),
                         d3 = libff::Fr<ppT>::random_element();

    libff::enter_block("Compute the polynomial H");
    const qap_witness<libff::Fr<ppT> > qap_wit = r1cs_to_qap_witness_map(crs.constraint_system, primary_input, auxiliary_input, d1, d2, d3);
    libff::leave_block("Compute the polynomial H");

#ifdef DEBUG
    const libff::Fr<ppT> t = libff::Fr<ppT>::random_element();
    qap_instance_evaluation<libff::Fr<ppT> > qap_inst = r1cs_to_qap_instance_map_with_evaluation(crs.constraint_system, t);
    assert(qap_inst.is_satisfied(qap_wit));
#endif

    NTL::ZZ_p::init(NTL::ZZ(LWE::q));

    libff::enter_block("Compute the proof");

    size_t num_inputs = qap_wit.num_inputs();
    size_t num_ABC_coeffs = qap_wit.coefficients_for_ABCs.size() - num_inputs;
    size_t proof_dim = num_ABC_coeffs + 3 + qap_wit.coefficients_for_H.size();
    LWE::vector pi(NTL::INIT_SIZE, proof_dim);
    for (size_t i = 0; i < num_ABC_coeffs; i++) {
        pi[i] = qap_wit.coefficients_for_ABCs[i + num_inputs].as_ZZ_p();
    }
    pi[num_ABC_coeffs]     = qap_wit.d1.as_ZZ_p();
    pi[num_ABC_coeffs + 1] = qap_wit.d2.as_ZZ_p();
    pi[num_ABC_coeffs + 2] = qap_wit.d3.as_ZZ_p();
    for (size_t i = 0; i < qap_wit.coefficients_for_H.size(); i++) {
        pi[num_ABC_coeffs + 3 + i] = qap_wit.coefficients_for_H[i].as_ZZ_p();
    }

    assert(proof_dim == crs.enc_queries.size());
    LWE::ciphertext ct = crs.enc_queries[0] * pi[0];
    for (size_t i = 1; i < proof_dim; i++) {
        ct += crs.enc_queries[i] * pi[i];
    }
    libff::leave_block("Compute the proof");

    libff::leave_block("Call to r1cs_lattice_ppsnarg_prover");

    r1cs_lattice_ppsnarg_proof<ppT> proof = r1cs_lattice_ppsnarg_proof<ppT>(std::move(ct));

    return proof;
}

template<typename ppT>
bool r1cs_lattice_ppsnarg_verifier(const r1cs_lattice_ppsnarg_verification_key<ppT> &vk,
                                     const r1cs_lattice_ppsnarg_primary_input<ppT> &primary_input,
                                     const r1cs_lattice_ppsnarg_proof<ppT> &proof) {
    bool result = true;

    libff::enter_block("Call to r1cs_lattice_ppsnarg_verifier");

    libff::enter_block("Decrypting proof");
    LWE::vector proof_decrypt = vk.Yprime*LWE::decrypt(vk.sk, proof.response);

    LWE::vector A(NTL::INIT_SIZE, r1cs_lattice_ppsnarg_num_queries);
    LWE::vector B(NTL::INIT_SIZE, r1cs_lattice_ppsnarg_num_queries);
    LWE::vector C(NTL::INIT_SIZE, r1cs_lattice_ppsnarg_num_queries);
    LWE::vector H(NTL::INIT_SIZE, r1cs_lattice_ppsnarg_num_queries);
    for (size_t i = 0; i < r1cs_lattice_ppsnarg_num_queries; i++) {
        A[i] = proof_decrypt[i];
        B[i] = proof_decrypt[i + r1cs_lattice_ppsnarg_num_queries];
        C[i] = proof_decrypt[i + 2*r1cs_lattice_ppsnarg_num_queries];
        H[i] = proof_decrypt[i + 3*r1cs_lattice_ppsnarg_num_queries];

        // Add in components corresponding to the constant term as well as the
        // components corresponding to the statement
        A[i] += vk.A_prefix[i][0].as_ZZ_p();
        B[i] += vk.B_prefix[i][0].as_ZZ_p();
        C[i] += vk.C_prefix[i][0].as_ZZ_p();

        for (size_t j = 0; j < primary_input.size(); j++) {
            A[i] += primary_input[j].as_ZZ_p() * vk.A_prefix[i][j + 1].as_ZZ_p();
            B[i] += primary_input[j].as_ZZ_p() * vk.B_prefix[i][j + 1].as_ZZ_p();
            C[i] += primary_input[j].as_ZZ_p() * vk.C_prefix[i][j + 1].as_ZZ_p();
        }
    }
    libff::leave_block("Decrypting proof");

    libff::Fr_vector<ppT> Z = vk.Z;

    libff::enter_block("Check QAP divisibility");
    NTL::ZZ_p::init(NTL::ZZ(LWE::p));
    for (size_t i = 0; i < r1cs_lattice_ppsnarg_num_queries; i++) {
        if (A[i]*B[i] != H[i]*Z[i].as_ZZ_p() + C[i]) {
            if (!libff::inhibit_profiling_info) {
                libff::print_indent(); printf("QAP divisiblity check failed.\n");
            }
            result = false;
        }
    }
    libff::leave_block("Check QAP divisibility");

    libff::leave_block("Call to r1cs_lattice_ppsnarg_verifier");
    return result;
}

} // libsnark

#endif // R1CS_LATTICE_PPSNARG_TCC_
