/** @file
 *****************************************************************************
 
 Arithmetic in the finite field Fp, for prime p of fixed length using
 NTL as the backend.

 *****************************************************************************
 * @author     Samir Menon, Brennan Shacklett, and David J. Wu
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef NTLFP_HPP_
#define NTLFP_HPP_

#include <cstddef>
#include <iostream>
#include <NTL/ZZ_p.h>
#include <libsnark/common/libsnark_serialization.hpp>
#include <libff/algebra/fields/bigint.hpp>

namespace libsnark {

template<unsigned long modulus>
class NTLFp_model;

template<unsigned long modulus>
std::ostream& operator<<(std::ostream &, const NTLFp_model<modulus>&);

template<unsigned long modulus>
std::istream& operator>>(std::istream &, NTLFp_model<modulus> &);

template<unsigned long modulus>
class NTLFp_model {
private:
    NTL::ZZ_p value;
public:
    static const constexpr unsigned long& mod = modulus;
    static size_t s; // log2(modulus) OR modulus = 2^s * t + 1
    static size_t t; // with t odd
    static NTLFp_model<modulus> multiplicative_generator; // generator of Fp^*
    static NTLFp_model<modulus> root_of_unity; // generator^((modulus-1)/2^s)m
    static size_t num_bits;

    NTLFp_model();
    NTLFp_model(long x);
    NTLFp_model(const NTLFp_model &other);
    NTLFp_model(const NTL::ZZ_p &value) : value(value) {}

    NTL::ZZ_p as_ZZ_p() const { return this->value; }
    static NTL::ZZ mod_zz() { return NTL::ZZ(modulus); }

    bool operator==(const NTLFp_model& other) const;
    bool operator!=(const NTLFp_model& other) const;
    bool is_zero() const;

    void print() const;

    NTLFp_model& operator+=(const NTLFp_model& other);
    NTLFp_model& operator-=(const NTLFp_model& other);
    NTLFp_model& operator*=(const NTLFp_model& other);
    NTLFp_model& operator/=(const NTLFp_model& other);
    NTLFp_model& operator^=(const NTLFp_model& other);
    NTLFp_model& operator^=(unsigned long pwr);
    NTLFp_model& operator^=(const libff::bigint<1>& pwr);

    NTLFp_model operator+(const NTLFp_model& other) const;
    NTLFp_model operator-(const NTLFp_model& other) const;
    NTLFp_model operator*(const NTLFp_model& other) const;
    NTLFp_model operator/(const NTLFp_model& other) const;
    NTLFp_model operator-() const;

    NTLFp_model squared() const;
    NTLFp_model& invert();
    NTLFp_model inverse() const;
    NTLFp_model sqrt() const;
    void get_s_and_t(unsigned long& s, unsigned long& t);

    NTLFp_model operator^(unsigned long pwr) const;
    NTLFp_model operator^(const libff::bigint<1>& pwr) const;
    NTLFp_model operator^(const NTLFp_model& other) const;
    

    static size_t size_in_bits() { return num_bits; }
    static size_t capacity() { return num_bits - 1; }
    static unsigned long field_char() { return modulus; }
    static NTLFp_model<modulus> geometric_generator() { return NTLFp_model<modulus>::multiplicative_generator; }
    static NTLFp_model<modulus> arithmetic_generator() { return 1; }

    static NTLFp_model<modulus> zero();
    static NTLFp_model<modulus> one();
    static NTLFp_model<modulus> random_element();

    friend std::ostream& operator<< <modulus>(std::ostream &out, const NTLFp_model<modulus> &p);
    friend std::istream& operator>> <modulus>(std::istream &in, NTLFp_model<modulus> &p);
};

template<unsigned long modulus>
size_t NTLFp_model<modulus>::num_bits;

template<unsigned long modulus>
size_t NTLFp_model<modulus>::s;

template<unsigned long modulus>
size_t NTLFp_model<modulus>::t;

template<unsigned long modulus>
NTLFp_model<modulus> NTLFp_model<modulus>::multiplicative_generator;

template<unsigned long modulus>
NTLFp_model<modulus> NTLFp_model<modulus>::root_of_unity;

} // libsnark

#include "ntlfp.tcc"

#endif // NTLFP_HPP_
