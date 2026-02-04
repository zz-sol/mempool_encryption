# Mempool Encryption API Design (HackMD)

## Goal
Design a unified trait-based API that supports both:
- **Interactive setup schemes** (multi-round DKG / VSS / etc.)
- **Silent setup schemes** (e.g., Tess) where interactive components are dummy/no-op

The API must allow interactive operation when needed, and allow silent-setup schemes to plug in
by implementing no-op steps while preserving the same interface.

## Terminology
- **Setup**: Produces public parameters and per-party secret shares/keys.
- **Release**: Threshold parties produce partial decryptions/signatures.
- **Combine**: Aggregates partials into a public witness (e.g., full signature).
- **Decrypt**: Anyone can decrypt using the public witness.

## Design Principles
- Single trait family covering both interactive and silent setups.
- Explicit message passing for interactive setups.
- Deterministic serialization boundaries for network transport.
- Keep cryptographic details inside scheme implementations.

## Core Types (Rust-like)
```rust
// Common identifiers
pub type PartyId = u32;

// For serialization / transport
pub trait Wire: Sized {
    fn encode(&self) -> Vec<u8>;
    fn decode(bytes: &[u8]) -> Result<Self, Error>;
}

#[derive(Clone, Debug)]
pub struct Params {
    pub n: u32,
    pub t: u32,
}

#[derive(Clone, Debug)]
pub struct PartyInfo {
    pub id: PartyId,
}
```

## Trait Family

### 1) Unified Setup Protocol
```rust
pub trait SetupProtocol {
    type PublicParams: Wire + Clone;
    type PartySecret: Wire + Clone;   // per-party share/key
    type SetupMessage: Wire + Clone;  // network message
    type SetupState;                  // local mutable state

    /// Initialize local state for party `me`.
    fn init(params: Params, me: PartyInfo) -> Self::SetupState;

    /// Advance protocol by handling an incoming message (if any).
    /// Returns a list of outgoing messages to broadcast/unicast.
    fn handle_message(
        state: &mut Self::SetupState,
        from: PartyId,
        msg: Self::SetupMessage,
    ) -> Result<Vec<(PartyId, Self::SetupMessage)>, Error>;

    /// Optional: called when a new round begins (for round-based protocols).
    fn begin_round(state: &mut Self::SetupState) -> Result<Vec<(PartyId, Self::SetupMessage)>, Error> {
        Ok(vec![])
    }

    /// Attempt to finalize after all required messages processed.
    fn finalize(
        state: Self::SetupState,
    ) -> Result<(Self::PublicParams, Self::PartySecret), Error>;
}
```

**Silent setup mapping (Tess):**
- `SetupMessage` can be `enum { Dummy }` or zero-sized.
- `init()` constructs state from local randomness / parameters.
- `handle_message()` ignores input and returns `Ok(vec![])`.
- `begin_round()` is no-op.
- `finalize()` returns immediately.

### 2) Threshold Release / Decryption
```rust
pub trait ThresholdRelease {
    type PublicParams: Wire + Clone;
    type PartySecret: Wire + Clone;
    type Ciphertext: Wire + Clone;
    type ReleaseTag: Wire + Clone;        // e.g., tg
    type PartialWitness: Wire + Clone;    // e.g., partial sig
    type FullWitness: Wire + Clone;       // e.g., full sig
    type Plaintext: Wire + Clone;

    /// Encrypt under public params and tag.
    fn encrypt(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        pt: &Self::Plaintext,
        rng: &mut dyn RngCore,
    ) -> Result<Self::Ciphertext, Error>;

    /// Produce a partial witness for tag using party secret.
    fn partial_release(
        pp: &Self::PublicParams,
        sk_i: &Self::PartySecret,
        tag: &Self::ReleaseTag,
    ) -> Result<Self::PartialWitness, Error>;

    /// Verify a partial witness.
    fn verify_partial(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        from: PartyId,
        w: &Self::PartialWitness,
    ) -> Result<(), Error>;

    /// Combine t partials into a full witness.
    fn combine(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        partials: &[(PartyId, Self::PartialWitness)],
    ) -> Result<Self::FullWitness, Error>;

    /// Anyone can decrypt using the full witness.
    fn decrypt(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        ct: &Self::Ciphertext,
        witness: &Self::FullWitness,
    ) -> Result<Self::Plaintext, Error>;
}
```

### 3) Unified Scheme (Setup + Release)
```rust
pub trait MempoolEncryptionScheme: SetupProtocol + ThresholdRelease<
    PublicParams = <Self as SetupProtocol>::PublicParams,
    PartySecret  = <Self as SetupProtocol>::PartySecret,
> {}
```

This ties setup to the release/decrypt API while keeping setup interactive if desired.

## Message Flow Examples

### Interactive DKG (multi-round)
1. `init()` creates local state.
2. `begin_round()` emits round-1 messages.
3. `handle_message()` processes incoming messages, emits responses.
4. Repeat for rounds.
5. `finalize()` outputs `(PublicParams, PartySecret)`.

### Silent Setup (Tess)
1. `init()` prepares state.
2. No messages exchanged.
3. `finalize()` returns immediately.

## Concrete Mapping to Spec (BLS DKG + Threshold Sig)
- `PublicParams`: BLS public key `PK`, group params, domain separators.
- `PartySecret`: secret share `x_i` plus any verification info.
- `ReleaseTag`: `tg` (byte string).
- `PartialWitness`: partial BLS signature `sigma_i`.
- `FullWitness`: aggregated signature `sigma`.
- `Ciphertext`: `(tg, U, C_K, N, C_M)`.

## Dummy Interactive Component for Tess
Provide a `SilentSetup` helper:
```rust
pub struct SilentSetup;

impl SetupProtocol for SilentSetup {
    type PublicParams = TessPublicParams;
    type PartySecret = TessPartySecret;
    type SetupMessage = ();
    type SetupState = TessLocalState;

    fn init(params: Params, me: PartyInfo) -> Self::SetupState { /* ... */ }
    fn handle_message(...){ Ok(vec![]) }
    fn finalize(state: Self::SetupState) -> Result<(Self::PublicParams, Self::PartySecret), Error> { /* ... */ }
}
```

## Two Instantiations

### 1) Tess (Silent Setup + Threshold Release)
```rust
pub struct TessScheme;

impl SetupProtocol for TessScheme {
    type PublicParams = TessPublicParams;   // includes public key, domain separators
    type PartySecret  = TessPartySecret;    // local share / trapdoor
    type SetupMessage = ();                 // no network messages
    type SetupState   = TessLocalState;

    fn init(params: Params, me: PartyInfo) -> Self::SetupState {
        TessLocalState::new(params, me)
    }

    fn handle_message(
        _state: &mut Self::SetupState,
        _from: PartyId,
        _msg: Self::SetupMessage,
    ) -> Result<Vec<(PartyId, Self::SetupMessage)>, Error> {
        Ok(vec![])
    }

    fn finalize(
        state: Self::SetupState,
    ) -> Result<(Self::PublicParams, Self::PartySecret), Error> {
        state.finalize()
    }
}

impl ThresholdRelease for TessScheme {
    type PublicParams    = TessPublicParams;
    type PartySecret     = TessPartySecret;
    type Ciphertext      = TessCiphertext;
    type ReleaseTag      = TessTag;
    type PartialWitness  = TessPartial;
    type FullWitness     = TessFull;
    type Plaintext       = TessPlaintext;

    fn encrypt(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        pt: &Self::Plaintext,
        rng: &mut dyn RngCore,
    ) -> Result<Self::Ciphertext, Error> {
        tess::encrypt(pp, tag, pt, rng)
    }

    fn partial_release(
        pp: &Self::PublicParams,
        sk_i: &Self::PartySecret,
        tag: &Self::ReleaseTag,
    ) -> Result<Self::PartialWitness, Error> {
        tess::partial_release(pp, sk_i, tag)
    }

    fn verify_partial(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        from: PartyId,
        w: &Self::PartialWitness,
    ) -> Result<(), Error> {
        tess::verify_partial(pp, tag, from, w)
    }

    fn combine(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        partials: &[(PartyId, Self::PartialWitness)],
    ) -> Result<Self::FullWitness, Error> {
        tess::combine(pp, tag, partials)
    }

    fn decrypt(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        ct: &Self::Ciphertext,
        witness: &Self::FullWitness,
    ) -> Result<Self::Plaintext, Error> {
        tess::decrypt(pp, tag, ct, witness)
    }
}

impl MempoolEncryptionScheme for TessScheme {}
```

### 2) DKG + BLS Threshold Signatures (Interactive Setup)
```rust
pub struct BlsDkgScheme;

impl SetupProtocol for BlsDkgScheme {
    type PublicParams = BlsPublicParams;   // PK, group params, domain separators
    type PartySecret  = BlsShare;          // x_i
    type SetupMessage = DkgMessage;        // VSS/DKG messages
    type SetupState   = DkgState;

    fn init(params: Params, me: PartyInfo) -> Self::SetupState {
        DkgState::new(params, me)
    }

    fn begin_round(state: &mut Self::SetupState) -> Result<Vec<(PartyId, Self::SetupMessage)>, Error> {
        state.begin_round()
    }

    fn handle_message(
        state: &mut Self::SetupState,
        from: PartyId,
        msg: Self::SetupMessage,
    ) -> Result<Vec<(PartyId, Self::SetupMessage)>, Error> {
        state.handle_message(from, msg)
    }

    fn finalize(
        state: Self::SetupState,
    ) -> Result<(Self::PublicParams, Self::PartySecret), Error> {
        state.finalize()
    }
}

impl ThresholdRelease for BlsDkgScheme {
    type PublicParams    = BlsPublicParams;
    type PartySecret     = BlsShare;
    type Ciphertext      = BlsKemCiphertext;
    type ReleaseTag      = BlsTag;         // tg
    type PartialWitness  = BlsPartialSig;  // sigma_i
    type FullWitness     = BlsFullSig;     // sigma
    type Plaintext       = BlsPlaintext;

    fn encrypt(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        pt: &Self::Plaintext,
        rng: &mut dyn RngCore,
    ) -> Result<Self::Ciphertext, Error> {
        bls_kem::encrypt(pp, tag, pt, rng)
    }

    fn partial_release(
        pp: &Self::PublicParams,
        sk_i: &Self::PartySecret,
        tag: &Self::ReleaseTag,
    ) -> Result<Self::PartialWitness, Error> {
        bls_sig::partial_sign(pp, sk_i, tag)
    }

    fn verify_partial(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        from: PartyId,
        w: &Self::PartialWitness,
    ) -> Result<(), Error> {
        bls_sig::verify_partial(pp, tag, from, w)
    }

    fn combine(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        partials: &[(PartyId, Self::PartialWitness)],
    ) -> Result<Self::FullWitness, Error> {
        bls_sig::combine(pp, tag, partials)
    }

    fn decrypt(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        ct: &Self::Ciphertext,
        witness: &Self::FullWitness,
    ) -> Result<Self::Plaintext, Error> {
        bls_kem::decrypt(pp, tag, ct, witness)
    }
}

impl MempoolEncryptionScheme for BlsDkgScheme {}
```

## Serialization and Domain Separation
- All `Wire` types must define canonical encoding and decoding.
- Tag binding and transcript hashes should include `scheme_id` to avoid cross-protocol replay.

## Open Questions
- Do we need explicit support for **complaints** in interactive setup?
- Do we want to standardize **round numbering** or allow arbitrary state machines?
- Should `verify_partial()` be optional for schemes without per-party verification?

## Next Step
If you want, I can turn this into concrete Rust traits and skeleton types in a new crate.
