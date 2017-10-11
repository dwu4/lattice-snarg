/** @file
 *****************************************************************************
 
 Arithmetic in the finite field Fp, for prime p of fixed length using
 NTL as the backend.

 *****************************************************************************
 * @author     Samir Menon, Brennan Shacklett, and David J. Wu
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef NTLFP_TCC_
#define NTLFP_TCC_

#include <cassert>
#include <cstdlib>
#include <cmath>
#include <NTL/ZZ.h>

#include <libff/algebra/fields/fp_aux.tcc>
#include <libff/algebra/fields/field_utils.hpp>

namespace libsnark {

template<unsigned long modulus>
NTLFp_model<modulus>::NTLFp_model()
{
    NTL::ZZ_p::init(mod_zz());
}

template<unsigned long modulus>
NTLFp_model<modulus>::NTLFp_model(long x)
{
    NTL::ZZ_p::init(mod_zz());
    this->value = x;
}

template <unsigned long modulus>
NTLFp_model<modulus>::NTLFp_model(const NTLFp_model &other)
{
    NTL::ZZ_p::init(mod_zz());
    this->value = other.value;
}

template<unsigned long modulus>
bool NTLFp_model<modulus>::operator==(const NTLFp_model& other) const
{
    return (this->value == other.value);
}

template<unsigned long modulus>
bool NTLFp_model<modulus>::operator!=(const NTLFp_model& other) const
{
    return (this->value != other.value);
}

template<unsigned long modulus>
bool NTLFp_model<modulus>::is_zero() const
{
    return NTL::IsZero(this->value);
}

template<unsigned long modulus>
void NTLFp_model<modulus>::print() const
{
    std::cout << *this;
}

template<unsigned long modulus>
NTLFp_model<modulus> NTLFp_model<modulus>::zero()
{
    NTL::ZZ_p::init(mod_zz());
    NTLFp_model<modulus> z(NTL::ZZ_p::zero());
    return z;
}

template<unsigned long modulus>
NTLFp_model<modulus> NTLFp_model<modulus>::one()
{
    NTL::ZZ_p::init(mod_zz());
    NTLFp_model<modulus> o(NTL::ZZ_p::zero() + 1);
    return o;
}

template<unsigned long modulus>
NTLFp_model<modulus>& NTLFp_model<modulus>::operator+=(const NTLFp_model<modulus>& other)
{
    NTL::ZZ_p::init(mod_zz());
    this->value += other.value;
    return *this;
}

template<unsigned long modulus>
NTLFp_model<modulus>& NTLFp_model<modulus>::operator-=(const NTLFp_model<modulus>& other)
{
    NTL::ZZ_p::init(mod_zz());
    this->value -= other.value;
    return *this;
}

template<unsigned long modulus>
NTLFp_model<modulus>& NTLFp_model<modulus>::operator*=(const NTLFp_model<modulus>& other)
{
    NTL::ZZ_p::init(mod_zz());
    this->value *= other.value;
    return *this;
}

template<unsigned long modulus>
NTLFp_model<modulus>& NTLFp_model<modulus>::operator^=(const NTLFp_model<modulus>& other)
{
    return this^=other.as_long();
}

template<unsigned long modulus>
NTLFp_model<modulus>& NTLFp_model<modulus>::operator^=(const libff::bigint<1>& pwr)
{
    return this^=pwr.as_ulong();
}

template<unsigned long modulus>
NTLFp_model<modulus>& NTLFp_model<modulus>::operator^=(const unsigned long pwr)
{
    NTL::ZZ_p::init(mod_zz());
    this->value = NTL::power(this->value, pwr);
    return (*this);
}

template<unsigned long modulus>
NTLFp_model<modulus> NTLFp_model<modulus>::operator+(const NTLFp_model<modulus>& other) const
{
    NTLFp_model<modulus> r(*this);
    return (r += other);
}

template<unsigned long modulus>
NTLFp_model<modulus> NTLFp_model<modulus>::operator-(const NTLFp_model<modulus>& other) const
{
    NTLFp_model<modulus> r(*this);
    return (r -= other);
}

template<unsigned long modulus>
NTLFp_model<modulus> NTLFp_model<modulus>::operator*(const NTLFp_model<modulus>& other) const
{
    NTLFp_model<modulus> r;
    NTL::mul(r.value, value, other.value);
    r.value = value * other.value;
    return r;
}

template<unsigned long modulus>
NTLFp_model<modulus> NTLFp_model<modulus>::operator^(const NTLFp_model<modulus>& other) const
{
    NTLFp_model<modulus> r(*this);
    return (r ^= other);
}

template<unsigned long modulus>
NTLFp_model<modulus> NTLFp_model<modulus>::operator^(const unsigned long pwr) const
{
    NTLFp_model<modulus> r(*this);
    return (r ^= pwr);
}

template<unsigned long modulus>
NTLFp_model<modulus> NTLFp_model<modulus>::operator^(const libff::bigint<1>& pwr) const
{
    NTLFp_model<modulus> r(*this);
    return (r ^= pwr.as_ulong());
}

template<unsigned long modulus>
NTLFp_model<modulus> NTLFp_model<modulus>::operator-() const
{
    NTLFp_model<modulus> r(modulus - this->value);
    return r;
}

template<unsigned long modulus>
NTLFp_model<modulus> NTLFp_model<modulus>::squared() const
{
    NTLFp_model<modulus> r(*this);
    return (r *= r);
}

template<unsigned long modulus>
NTLFp_model<modulus>& NTLFp_model<modulus>::invert()
{
    NTL::ZZ_p inverse = 1 / this->value;;
    this->value = inverse;
    return *this;
}

template<unsigned long modulus>
NTLFp_model<modulus> NTLFp_model<modulus>::inverse() const
{
    NTLFp_model<modulus> r(*this);
    return r.invert();
}

template<unsigned long modulus>
NTLFp_model<modulus> NTLFp_model<modulus>::random_element()
{
    NTL::ZZ_p::init(mod_zz());
    NTLFp_model<modulus> r;
    r.value = NTL::ZZ_p(NTL::RandomBnd(modulus));
    return r;
}

template<unsigned long modulus>
void NTLFp_model<modulus>::get_s_and_t(unsigned long& s, unsigned long& t)
{
    s = modulus - 1;
    t = 0;
    while (s % 2 == 0) {
        s /= 2;
        t++;
    }
}

template<unsigned long modulus>
NTLFp_model<modulus> NTLFp_model<modulus>::sqrt() const
{
    NTL::ZZ_p::init(mod_zz());
    NTL::ZZ_p sqrt = NTL::to_ZZ_p(NTL::SqrRootMod(NTL::rep(this->value), mod_zz()));
    NTLFp_model<modulus> root;
    root.value = sqrt;

    return root;
}

template<unsigned long modulus>
std::ostream& operator<<(std::ostream &out, const NTLFp_model<modulus> &p)
{
    out << p.value;
    return out;
}

template<unsigned long modulus>
std::istream& operator>>(std::istream &in, NTLFp_model<modulus> &p)
{
    in >> p.value;
    return in;
}

} // libsnark

#endif // NTLFP_TCC_
