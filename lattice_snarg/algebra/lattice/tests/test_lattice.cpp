/** @file
*****************************************************************************

Basic test case for the secret-key lattice-based additively homomorphic
vector encryption scheme.

*****************************************************************************
* @author     Samir Menon, Brennan Shacklett, and David J. Wu
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#include <libff/common/profiling.hpp>
#include <lattice_snarg/algebra/lattice/lwe.hpp>
#include <lattice_snarg/algebra/fields/ntlfp.hpp>
#include <cinttypes>

using namespace std;
using namespace libsnark;

typedef NTLFp_model<LWE::p_int> Fr;

LWE::plaintext field_vector_to_lwe_pt(const Fr *v) {
    LWE::plaintext pt(NTL::INIT_SIZE, LWE::pt_dim);
    for (uint32_t i = 0; i < LWE::pt_dim; i++) {
        pt[i] = v[i].as_ZZ_p();
    }
    return pt;
}

bool check_relation(const Fr &lhs, const Fr &rhs, const string &check, int i) {
    if (lhs != rhs) {
        cout << check << " (index " << i << "): " << lhs << " != " << rhs << endl;
    }

    return (lhs == rhs);
}

int main() {
    bool success = true;

    srand(time(NULL));

    int c1 = rand() % LWE::p_int;
    int c2 = rand() % LWE::p_int;
    Fr c1p = Fr(c1);
    Fr c2p = Fr(c2);

    printf("Testing that %i*a + %i*b can be computed with ciphertexts (encrypt, add/multiply, decrypt), where a,b are vectors\n", c1, c2);

    Fr d1[LWE::pt_dim];
    Fr d2[LWE::pt_dim];
    for (uint32_t i = 0; i < LWE::pt_dim; i++) {
        d1[i] = Fr::random_element();
        d2[i] = Fr::random_element();
    }
    LWE::plaintext d1i = field_vector_to_lwe_pt(d1);
    LWE::plaintext d2i = field_vector_to_lwe_pt(d2);

    LWE::secret_key LWE_sk = LWE::keygen();

    LWE::ciphertext ct1 = LWE::encrypt(LWE_sk, d1i);
    LWE::ciphertext ct2 = LWE::encrypt(LWE_sk, d2i);
    LWE::plaintext out1 = LWE::decrypt(LWE_sk, ct1);
    LWE::plaintext out2 = LWE::decrypt(LWE_sk, ct2);
    for (uint32_t i = 0; i < LWE::pt_dim; i++) {
        success = check_relation(d1[i], out1[i], "Decryption 1", i) && success;
    }

    for (uint32_t i = 0; i < LWE::pt_dim; i++) {
        success = check_relation(d2[i], out2[i], "Decryption 2", i) && success;
    }

    NTL::ZZ_p::init(NTL::ZZ(LWE::q));
    LWE::plaintext outadd = LWE::decrypt(LWE_sk, ct1 + ct2);
    for (uint32_t i = 0; i < LWE::pt_dim; i++) {
        success = check_relation(d1[i] + d2[i], outadd[i], "Sum", i) && success;
    }

    NTL::ZZ_p::init(NTL::ZZ(LWE::q));
    LWE::plaintext outmult = LWE::decrypt(LWE_sk, c1*ct1);
    for (uint32_t i = 0; i < LWE::pt_dim; i++) {
        success = check_relation(c1p*d1[i], outmult[i], "Scalar Multiplication", i) && success;
    }

    NTL::ZZ_p::init(NTL::ZZ(LWE::q));
    LWE::plaintext out = LWE::decrypt(LWE_sk, c1*ct1+c2*ct2);
    for (uint32_t i = 0; i < LWE::pt_dim; i++) {
        success = check_relation(c1p*d1[i]+c2p*d2[i], out[i], "Linear Relation", i) && success;
    }

    if (success) {
        cout << "All tests passed." << endl;
    }
}
