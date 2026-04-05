# Benchmarks

Encrypt/decrypt throughput for `chacha20blake3` across message sizes from 64 B to 64 MiB.

## Environment

- **CPU:** Intel Core i7-9750H @ 2.60 GHz (AVX2, Linux VM on 2019 MacBook Pro)
- **Ruby:** 4.0.2 +YJIT / x86_64-linux
- **Build:** `--release`, LTO, `target-cpu=native`
- **chacha20blake3:** 0.1.0

## Results

```
Size            Encrypt      Decrypt  Enc throughput  Dec throughput
--------------------------------------------------------------------
64 B             1.1 µs       1.1 µs       55.8 MB/s       56.1 MB/s
128 B            1.3 µs       1.3 µs       97.6 MB/s       96.2 MB/s
256 B            1.4 µs       1.6 µs      178.6 MB/s      164.3 MB/s
512 B            1.6 µs       1.6 µs      316.1 MB/s      316.7 MB/s
1 KiB            2.6 µs       2.6 µs      399.7 MB/s      391.0 MB/s
2 KiB            4.2 µs       4.2 µs      491.4 MB/s      492.2 MB/s
4 KiB            6.4 µs       6.5 µs      635.4 MB/s      628.6 MB/s
8 KiB           11.3 µs      10.5 µs      722.7 MB/s      781.6 MB/s
16 KiB          16.8 µs      17.1 µs      973.7 MB/s      958.6 MB/s
32 KiB          30.8 µs      30.4 µs       1.06 GB/s       1.08 GB/s
64 KiB          55.8 µs      57.3 µs       1.18 GB/s       1.14 GB/s
128 KiB        109.5 µs     107.9 µs       1.20 GB/s       1.22 GB/s
256 KiB        220.6 µs     217.3 µs       1.19 GB/s       1.21 GB/s
512 KiB        423.5 µs     438.4 µs       1.24 GB/s       1.20 GB/s
1 MiB          865.0 µs     865.1 µs       1.21 GB/s       1.21 GB/s
2 MiB           1.91 ms      1.79 ms       1.10 GB/s       1.17 GB/s
4 MiB           4.82 ms      4.71 ms      870.2 MB/s      891.0 MB/s
8 MiB          11.08 ms      8.40 ms      757.3 MB/s      999.0 MB/s
16 MiB         23.40 ms     22.09 ms      716.9 MB/s      759.5 MB/s
32 MiB         61.23 ms     61.64 ms      548.0 MB/s      544.4 MB/s
64 MiB        126.59 ms    126.25 ms      530.1 MB/s      531.6 MB/s
```

## Notes

- **Fixed overhead** is ~1 µs per operation (KDF + FFI crossing), dominating at small sizes.
- **Peak throughput** of ~1.24 GB/s occurs around 128 KiB-1 MiB (L2/L3 cache sweet spot).
- **Large messages** (>2 MiB) see declining throughput due to L3 cache eviction, GC pressure, and memory-bandwidth saturation.
- Compiled with `-C target-cpu=native` to enable AVX2 auto-vectorization of the ChaCha20 XOR loop and BLAKE3 assembly. Without this flag, throughput drops ~16x to ~55 MB/s. See [upstream PR #12](https://github.com/skerkour/chacha20-blake3/pull/12) for the proper fix.

## Reproduce

```sh
bundle exec rake bench
```
