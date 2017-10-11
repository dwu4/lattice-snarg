Lattice-Based SNARGs over libsnark
================================================================================

This is a prototype implementation of a lattice-based succinct non-interactive
argument (SNARG) built on top of the [libsnark](https://github.com/scipr-lab/libsnark)
library. All of the code is released under the MIT License (see
the [LICENSE] file).

**Warning:** This code is intended as a research prototype and a proof-of-concept
implementation of a lattice-based SNARG. It is not intended to be used in
critical or production-level systems.

This library is currently maintained by David Wu (dwu4@cs.stanford.edu). See [AUTHORS]
for a full list of contributors.

--------------------------------------------------------------------------------
Overview
--------------------------------------------------------------------------------

We refer to the [libsnark README](https://github.com/scipr-lab/libsnark) for
an overview of succinct non-interactive argument (SNARG) systems.
This library provides an implementation of the
lattice-based SNARG described in \[BISW17] for the R1CS (rank-1 constraint
systems) language. Our implementation relies on the QAP building blocks from
libsnark together with a variant of the the vector encryption scheme from
\[LP10].

The parameters in this prototype implementation are chosen to support
verifying R1CS instances whose QAP representations has degree up to a maximum
of ~10000 (roughly corresponding to R1CS instances with 10000 constraints and
a small number of inputs). All of the parameters are chosen to provide 80 bits
of security and soundness error 1 - 2^{-40}.


-------------------------------------------------------------------------------
Build instructions
-------------------------------------------------------------------------------

### Dependencies

The lattice-based SNARG library relies on the following:

- C++ build environment
- CMake build infrastructure
- GMP for big-integer arithmetic
- NTL (over GMP) for finite field arithmetic
- libsnark (fetched and compiled via Git submodules)

Here are the requisite packages on Ubuntu:

* On Ubuntu:

        $ sudo apt-get install build-essential cmake git libgmp3-dev libprocps4-dev python-markdown libboost-all-dev libssl-dev libntl-dev

### Building

Fetch the libsnark submodule

    $ git submodule update --init

Fetch the libsnark dependencies

    $ cd libsnark && git submodule update --init && cd ..

Create the Makefile:

    $ mkdir build && cd build && cmake ..

To compile the library and the tests, run this within the `build/` directory:

    $ make

-------------------------------------------------------------------------------
Running example
-------------------------------------------------------------------------------

The command (run from the `build/` directory)

    $ ./lattice_snarg/r1cs_lattice_snarg_test 1000 10

exercises the SNARG (i.e., samples a CRS and a verification key, invokes the
prover on a statement, and then invokes the verifier on the proof) on a rank-1
constraint system instance with 1000 constraints and an input consisting of 10
field elements. The rank-1 constraint system used in this example is taken
from libsnark.

--------------------------------------------------------------------------------
References
--------------------------------------------------------------------------------

\[BISW17]
  [Lattice-Based SNARGs and Their Application to More Efficient Obfuscation](https://eprint.iacr.org/2017/240).
  Dan Boneh, Yuval Ishai, Amit Sahai, and David J. Wu.
  Eurocrypt, 2017.

\[LP10]: [Better Key Sizes (and Attacks) for
  LWE-Based Encryption](https://eprint.iacr.org/2010/613).
  Richard Lindner and Chris Peikert. CT-RSA, 2011.

[AUTHORS]: AUTHORS (AUTHORS file in top directory)

[LICENSE]: LICENSE (LICENSE file in top directory)
