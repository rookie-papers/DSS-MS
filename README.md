# Cryptographic Experiment Template Based on MIRACL Core

This repository provides a reusable project template for students and researchers working on cryptographic experiments. It integrates the [MIRACL Core](https://github.com/miracl/core) cryptographic library, along with the GMP library for large integer operations, and a benchmarking module for performance evaluation.

---

## Features

- **Built-in [MIRACL Core](https://github.com/miracl/core)**  
  The project includes the MIRACL Core cryptographic library as a submodule. It provides support for a wide range of cryptographic primitives, including elliptic curves, pairing-friendly curves, RSA, and more. By default, the library is configured to use the `BLS12381` pairing-friendly curve.

- **Seamless integration with [GMP](https://gmplib.org/)**  
  MIRACL’s internal `BIG` type is powerful but cumbersome for general-purpose big integer arithmetic. This template integrates the GMP (GNU Multiple Precision Arithmetic Library) to provide a more convenient interface using C++’s `mpz_class`. It enables easy manipulation of large integers with native arithmetic syntax and high performance.

- **Utility class for MIRACL-GMP interoperability and common crypto routines**  
  Provides convenient conversion between `mpz_class` and `BIG`, along with wrappers for random number generation, hashing, secret sharing, and formatted debugging output — making cryptographic experimentation faster and more intuitive.

- **Integrated [Google Benchmark](https://github.com/google/benchmark)** module  
  Performance analysis is crucial in cryptographic research. This template includes Google Benchmark to help users write and run precise micro-benchmarks on their cryptographic operations. It allows accurate measurement of latency and throughput for operations like key generation, signing, verification, scalar multiplication, and more.



By default, the selected elliptic curve in MIRACL is `BLS12381`.
To switch to a different curve. Edit the configuration script at:
  
```bash
  external/run_miracl_config.sh
```

---



## Usage

### Option 1: Clone, build, and run example tests

You can quickly get started by cloning the template, building the project, and running the included sample functions. These examples demonstrate how to perform basic cryptographic operations using MIRACL and GMP, and serve as a foundation for further experiments.

Clone and update submodule using:
```bash
git clone git@github.com:rookie-papers/template-miracl-exp.git your_exp_name
cd your_exp_name
git submodule update --init --recursive
```

You can then run the tests using:
```bash
mkdir build && cd build
cmake ..
make
./your_exp_exe    
```


### Option 2: Clone and reset as a new project (remove commit history)

If you'd like to use this template as a clean base for a new cryptographic project without inheriting the original Git history, you can reinitialize it as a fresh repository:

```bash
git clone git@github.com:rookie-papers/template-miracl-exp.git your_exp_name
cd your_exp_name
rm -rf .git
git init
git add .
git commit -m "feat: initialize cryptographic experiment project"
```
This is especially useful when creating an independent implementation for your own scheme or paper.
If you want to implement and compare multiple cryptographic schemes, you can organize them as parallel subdirectories (e.g., your_exp, baseline_exp, optimized_exp) under the root directory.
To include a new scheme in the build system, simply register its main file in CMakeLists.txt:

```bash
add_scheme_executable(your_new_exp)
```
