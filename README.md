# Mempool Encryption (DKG + Threshold BLS + KEM)

This crate implements the protocol described in `docs/mempool_encryption_spec.md` using BLS12-381 (blstrs), Pedersen VSS DKG, threshold BLS signatures, and a pairing-based KEM with AEAD payload encryption.

## Status
- DKG with Pedersen VSS commitments
- Signed messages + transcript hash
- Complaint + share opening resolution
- Threshold BLS signatures
- KEM + AEAD encryption/decryption
- Extensive tests (happy path + negative cases)

## Layout
- `src/dkg.rs`: DKG state machine, messages, complaint handling, transcript hash
- `src/kem.rs`: threshold signature + KEM/AEAD encryption/decryption
- `src/bls.rs`: hash-to-curve, pairing, serialization helpers
- `src/encoding.rs`: length-prefixed encoding helpers
- `src/lagrange.rs`: Lagrange interpolation helpers
- `src/scheme.rs`: unified traits
- `examples/roundtrip.rs`: end-to-end demo

## Protocol Overview (Spec Mapping)

### 1) DKG (Pedersen VSS)
- Each party samples polynomials `f_j(z)` and `r_j(z)` and broadcasts commitments:
  `C_{j,k} = g2^{a_{j,k}} h2^{b_{j,k}}`.
- Each party sends shares `(f_j(i), r_j(i))` to each participant.
- Recipients verify shares against commitments and broadcast **signed complaints** on failure.
- Accused dealers broadcast **ShareOpen** with the disputed share.
- Invalid openings disqualify dealers; unresolved complaints disqualify dealers.
- QUAL set is the remaining dealers; each party sums qualified shares to derive `x_i`.
- Each party’s public share `PK_i = g2^{x_i}` is collected and used to reconstruct group `PK`.
- A transcript hash over all verified messages is produced for auditability.

### 2) Threshold BLS Signatures
- For tag `tg`, party `i` produces partial signature `sigma_i = H(tg)^{x_i}`.
- Partial signatures are verified via `e(sigma_i, g2) == e(H(tg), PK_i)`.
- Any `t` partials are combined via Lagrange interpolation to obtain `sigma = H(tg)^x`.

### 3) KEM + AEAD
- Encryptor chooses random `r`, computes `U = g2^r`.
- Derives shared `W = e(H(tg), PK)^r`, then HKDF to mask symmetric key.
- Encrypts payload with AEAD using associated data `enc(tg, U, PK)`.
- Decryptor uses published `sigma` to compute `W' = e(sigma, U)` and recover the key.

## Usage
Run tests:
```bash
cargo test
```

Run the demo:
```bash
cargo run --example roundtrip
```

Enable logging:
```bash
RUST_LOG=info cargo run --example roundtrip
```

## Notes / Limitations
- The network/transport layer is not implemented; tests and examples simulate message delivery in-memory.
- DKG timeouts and consensus on QUAL are outside the scope of this crate.
- `PK` is reconstructed from collected `PK_i` shares (Pedersen commitments hide `PK`).

## Spec References
- See `docs/mempool_encryption_spec.md` for the full cryptographic specification (and `docs/mempool_encryption_spec.pdf` for the PDF).
