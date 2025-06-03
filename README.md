# Dynamic Sanitizable Signature with Multiple Sanitizers
This repository presents the implementation of DSS-MS (Dynamic Sanitizable Signature with Multiple Sanitizers), 
a signature scheme designed to support dynamic redaction by multiple sanitizers. 
In addition to DSS-MS, the project includes implementations of several recent schemes
— DVAS, BFLS10, and IBSDIA — for experimental comparison. 
The repository simulates the communication process using WebSocket and evaluates the 
performance of each scheme through detailed benchmarking.

---

## ⚙️ Build Instructions

The following instructions guide you through installing dependencies, building the project, and running the benchmark and WebSocket-based versions.

### 1️⃣ Install Required Dependencies

Run the following command to install all dependencies necessary for building this project:

- `m4`: required for building GMP
- `libboost-all-dev`: required for building `websocketpp`
- Other standard tools: `git`, `cmake`, `python3`, `build-essential`

```bash
sudo apt update
sudo apt install -y git cmake python3 build-essential m4 libboost-all-dev
```

### 2️⃣ Clone repository with submodules and build with CMake:

```bash
git clone --recurse-submodules https://github.com/rookie-papers/DSS-MS.git
cd DSS-MS
mkdir build && cd build
cmake ..
make 
```

### 3️⃣ Running Benchmarks Executables
After a successful build, each scheme will produce a separate benchmark executable in the build/ directory:
Run them in sequence and check the performance comparison results

```bash
./DSS_exec
./DVAS_exec
./BFLS10_exec
./IBSDIA_exec
```

### 4️⃣ Run the WebSocket-Based DSS-MS

After building, the WebSocket-based version is located in the build/DSS-websocket directory. It includes three executables:

- Verifier_exec: represents the verifier
- Sanitizer_exec: represents the sanitizer
- Signer_exec: represents the signer

Start the three programs in the following order: the Signer generates a signature and sends it to the Sanitizer, which processes (sanitizes) the signature and forwards it to the Verifier. The Verifier then validates the received signature.

By default:
- The Verifier listens on port 9003
- The Sanitizer listens on port 9002

If you want to run the components on different machines, be sure to update the WebSocket URIs accordingly.
```bash
./Verifier_exec
./Sanitizer_exec
./Signer_exec
```

### 5️⃣ Test Scheme Correctness (Optional)
Each scheme includes test code in the main function. By default, this code is commented out to allow benchmarking.
To run functional tests instead, comment out the benchmark code and uncomment the main function in the corresponding source files.


## 📦 Dependencies

All dependencies are included as Git submodules:

| Library          | Source URL                                                                       |
|------------------|----------------------------------------------------------------------------------|
| GMP              | [github.com/rookie-papers/GMP](https://github.com/rookie-papers/GMP) (via fork with CMake support) |
| MIRACL Core      | [github.com/miracl/core](https://github.com/miracl/core)                         |
| Google Benchmark | [github.com/google/benchmark](https://github.com/google/benchmark)               |
| Websocketpp      | [github.com/zaphoyd/websocketpp](https://github.com/zaphoyd/websocketpp)               |
You don't need to install them manually — they are automatically configured and built with CMake.
