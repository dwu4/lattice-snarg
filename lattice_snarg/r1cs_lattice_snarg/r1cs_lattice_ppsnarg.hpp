/** @file
 *****************************************************************************

 Declaration of interfaces for a ppSNARG for R1CS.

 This includes:
 - class for common reference string (CRS)
 - class for secret verification key
 - class for key pair (CRS & verification key)
 - class for proof
 - generator algorithm
 - prover algorithm
 - verifier algorithm

 The implementation instantiates (a modification of) the lattice-based SNARG
 construction from [BISW17] using the QAP-based linear PCP of [BCGTV13].

 Acronyms:

 - R1CS = "Rank-1 Constraint Systems"
 - ppSNARG = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument"

References:

 [BISW17]:  Dan Boneh, Yuval Ishai, Amit Sahai, and David J. Wu. Lattice-Based SNARGs and Their
            Application to More Efficient Obfuscation. In Eurocrypt, 2017.

 [BCGTV13]: Eli Ben-Sasson, Alessandro Chiesa, Daniel Genkin, Eran Tromer, and Madars Virza.
            SNARKs for C: Verifying Program Executions Succinctly and in Zero Knowledge. In
            Crypto, 2013.

 *****************************************************************************
 * @author     Samir Menon, Brennan Shacklett, and David J. Wu
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef R1CS_LATTICE_PPSNARG_HPP_
#define R1CS_LATTICE_PPSNARG_HPP_

#include <memory>

#include <libff/algebra/curves/public_params.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <lattice_snarg/algebra/lattice/lwe.hpp>
#include <lattice_snarg/r1cs_lattice_snarg/r1cs_lattice_ppsnarg_params.hpp>

namespace libsnark {

// Number of queries of the underlying linear PCP (for soundness amplification)
const int r1cs_lattice_ppsnarg_num_queries = LWE::l;

/******************************** Proving key ********************************/

template<typename ppT>
class r1cs_lattice_ppsnarg_crs;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_lattice_ppsnarg_crs<ppT> &crs);

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_lattice_ppsnarg_crs<ppT> &crs);

/**
 * The common reference string
 */
template<typename ppT>
class r1cs_lattice_ppsnarg_crs {
public:
    std::vector<LWE::ciphertext> enc_queries;

    r1cs_lattice_ppsnarg_constraint_system<ppT> constraint_system;

    r1cs_lattice_ppsnarg_crs() {};
    r1cs_lattice_ppsnarg_crs<ppT>& operator=(const r1cs_lattice_ppsnarg_crs<ppT> &other) = default;
    r1cs_lattice_ppsnarg_crs(const r1cs_lattice_ppsnarg_crs<ppT> &other) = default;
    r1cs_lattice_ppsnarg_crs(r1cs_lattice_ppsnarg_crs<ppT> &&other) = default;
    r1cs_lattice_ppsnarg_crs(std::vector<LWE::ciphertext> &&enc_queries,
                             const r1cs_lattice_ppsnarg_constraint_system<ppT> &constraint_system) :
        enc_queries(std::move(enc_queries)),
        constraint_system(constraint_system)
    {};
};


/******************************* Verification key ****************************/

template<typename ppT>
class r1cs_lattice_ppsnarg_verification_key;

/**
 * A verification key for the R1CS ppSNARG.
 */
template<typename ppT>
class r1cs_lattice_ppsnarg_verification_key {
public:
    LWE::secret_key sk;
    libff::Fr_vector<ppT> Z;
    LWE::matrix Yprime;

    std::vector<libff::Fr_vector<ppT>> A_prefix;
    std::vector<libff::Fr_vector<ppT>> B_prefix;
    std::vector<libff::Fr_vector<ppT>> C_prefix;

    r1cs_lattice_ppsnarg_verification_key() = default;
    r1cs_lattice_ppsnarg_verification_key(LWE::secret_key &&sk,
                                          libff::Fr_vector<ppT> &&Z,
                                          LWE::matrix &&Yprime,
                                          std::vector<libff::Fr_vector<ppT>> &&A_prefix,
                                          std::vector<libff::Fr_vector<ppT>> &&B_prefix,
                                          std::vector<libff::Fr_vector<ppT>> &&C_prefix) : 
        sk(std::move(sk)),
        Z(std::move(Z)),
        Yprime(std::move(Yprime)),
        A_prefix(std::move(A_prefix)),
        B_prefix(std::move(B_prefix)),
        C_prefix(std::move(C_prefix))
    {}
};

/********************************** Key pair *********************************/

/**
 * A key pair for the R1CS ppzkSNARK, which consists of a proving key and a verification key.
 */
template<typename ppT>
class r1cs_lattice_ppsnarg_keypair {
public:
    r1cs_lattice_ppsnarg_crs<ppT> crs;
    r1cs_lattice_ppsnarg_verification_key<ppT> vk;

    r1cs_lattice_ppsnarg_keypair() = default;
    r1cs_lattice_ppsnarg_keypair(const r1cs_lattice_ppsnarg_keypair<ppT> &other) = default;
    r1cs_lattice_ppsnarg_keypair(r1cs_lattice_ppsnarg_crs<ppT> &&crs,
                           r1cs_lattice_ppsnarg_verification_key<ppT> &&vk) :
        crs(std::move(crs)),
        vk(std::move(vk))
    {}

    r1cs_lattice_ppsnarg_keypair(r1cs_lattice_ppsnarg_keypair<ppT> &&other) = default;
};


/*********************************** Proof ***********************************/

template<typename ppT>
class r1cs_lattice_ppsnarg_proof;

/**
 * A proof for the R1CS ppSNARG.
 */
template<typename ppT>
class r1cs_lattice_ppsnarg_proof {
public:
    LWE::ciphertext response;

    r1cs_lattice_ppsnarg_proof() {}
    r1cs_lattice_ppsnarg_proof(LWE::ciphertext &&response) 
        : response(response)
    {}
};


/***************************** Main algorithms *******************************/

/**
 * A generator algorithm for the R1CS ppSNARG.
 *
 * Given a R1CS constraint system CS, this algorithm computes a CRS
 * and a verification keys for CS.
 */
template<typename ppT>
r1cs_lattice_ppsnarg_keypair<ppT> r1cs_lattice_ppsnarg_generator(const r1cs_lattice_ppsnarg_constraint_system<ppT> &cs);

/**
 * A prover algorithm for the R1CS ppSNARG.
 *
 * Given a R1CS primary input X and a R1CS auxiliary input Y, this algorithm
 * produces a proof that attests to the following statement:
 *               ``there exists Y such that CS(X,Y)=0''.
 * Above, CS is the R1CS constraint system that was given as input to the generator algorithm.
 */
template<typename ppT>
r1cs_lattice_ppsnarg_proof<ppT> r1cs_lattice_ppsnarg_prover(const r1cs_lattice_ppsnarg_crs<ppT> &crs,
                                                            const r1cs_lattice_ppsnarg_primary_input<ppT> &primary_input,
                                                            const r1cs_lattice_ppsnarg_auxiliary_input<ppT> &auxiliary_input);

/**
 * A verifier algorithm for the R1CS ppSNARG
 */
template<typename ppT>
bool r1cs_lattice_ppsnarg_verifier(const r1cs_lattice_ppsnarg_verification_key<ppT> &vk,
                                   const r1cs_lattice_ppsnarg_primary_input<ppT> &primary_input,
                                   const r1cs_lattice_ppsnarg_proof<ppT> &proof);
} // libsnark

#include <lattice_snarg/r1cs_lattice_snarg/r1cs_lattice_ppsnarg.tcc>

#endif // R1CS_LATTICE_PPSNARG_HPP_
