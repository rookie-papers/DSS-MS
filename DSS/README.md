# DSS-MS CRT benchmark

Build the `DSS_exec` target from the repository root. It uses the project's MIRACL and GMP dependencies.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBENCHMARK_ENABLE_WERROR=OFF
cmake --build build --target DSS_exec -j 2
build/DSS_exec --check
build/DSS_exec --output "$PWD/build/results/jetson"
```

The default matrix uses 30 independent timing repeats, eight operations per repeat for short operations, one per repeat for expensive operations, and one warm-up repeat. It covers 2 to 10,000 authorized members and 1,000 GCD trials per history. To validate the pipeline first, pass `--smoke --repeats 2 --iterations 2 --history-trials 5` and a fresh output directory. The runner writes raw samples as it goes. A completed run contains `complete.txt`.

Copy the entire result directory to a machine with Python and Matplotlib. Run `python3 /path/to/results/plot_results.py`. The script reads the CSV files beside it, writes six figures in PDF and PNG, and computes summaries from the raw repeats. The communication figure models application payload and uses one recipient plus a configurable fanout (`--receivers`). The CSV records each modeled message and recipient, with component bytes from the canonical encoding where implemented. The five requested membership scales include the exact integer bit length of the residue and the byte lengths of its encoding and the whole manifest. Since the residue is smaller than the product of the moduli, its bit length is bounded by the sum of the modulus bit lengths, at most 256 bits per member. The manifest additionally carries each 32-byte modulus and 8-byte member ID. Transport, security-channel framing and connection establishment are external to the byte model. The legacy WebSocket demo remains a separate experiment.

The implementation uses 32-byte scalars and 49-byte compressed G1 points, for a 162-byte DSS signature in this encoding. Baseline timing is collected for a 256-byte, two-block order with one modified block. IUT-k-SAN uses two sanitizers and a 3072-bit Paillier modulus. PF-CLSS-DV is its native single instance with a designated verifier. The signature-size table labels both baseline size rows as formulas. Membership updates use the same starting member count for each repeat. The sender's generation and the receiver's first acceptance are timed separately from steady-state order operations.

The TA signs one canonical manifest per epoch. Its authenticated bytes include the version, system, epoch, nonce, status, sorted member IDs and moduli, sanitizer public key, and the CRT residue. PRF input binds a SHA-256 digest of that context, the member ID and a counter. Order processing takes an authenticated epoch and a caller-supplied trusted epoch floor. The caller owns storage of the floor, authenticated epoch distribution, signer key registration, and persistent audit storage. Run archive verification with the corresponding authenticated historical epoch. The correctness entry point checks this path separately from current dispatch.

On a Jetson with `tegrastats`, the companion energy collector accepts the power rail reported by that device.

```sh
python3 build/results/jetson/collect_energy.py build/DSS_exec build/results/jetson \
  --rail VDD_IN --operation Join Revoke AcceptEpoch --members 100 --batch 10
```

The collector records paired active and idle windows in `energy.csv` and raw readings in `power_samples.csv`. Choose the actual rail name exposed by the hardware. Repeat plotting after collection to add the energy figure. Join and Revoke energy includes the per-operation fixture copy used to restore the starting membership. Link measurements are independent of this runner.
