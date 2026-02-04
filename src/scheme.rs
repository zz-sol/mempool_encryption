//! Trait definitions for setup and threshold release.

use rand_core::RngCore;

use crate::types::{Error, Params, PartyId, PartyInfo, Wire};

pub trait SetupProtocol {
    // Types exposed by the setup protocol.
    type PublicParams: Wire + Clone;
    type PartySecret: Wire + Clone;
    type SetupMessage: Wire + Clone;
    type SetupState;

    // Initialize local protocol state for one party.
    fn init(params: Params, me: PartyInfo) -> Self::SetupState;

    // Process an incoming message and return any outgoing messages.
    fn handle_message(
        state: &mut Self::SetupState,
        from: PartyId,
        msg: Self::SetupMessage,
    ) -> Result<Vec<(PartyId, Self::SetupMessage)>, Error>;

    // Optional hook for round-based protocols.
    fn begin_round(
        state: &mut Self::SetupState,
    ) -> Result<Vec<(PartyId, Self::SetupMessage)>, Error> {
        let _ = state;
        Ok(vec![])
    }

    // Finalize and output public params + local secret share.
    fn finalize(state: Self::SetupState) -> Result<(Self::PublicParams, Self::PartySecret), Error>;
}

pub trait ThresholdRelease {
    // Types used for encryption and release.
    type PublicParams: Wire + Clone;
    type PartySecret: Wire + Clone;
    type Ciphertext: Wire + Clone;
    type ReleaseTag: Wire + Clone;
    type PartialWitness: Wire + Clone;
    type FullWitness: Wire + Clone;
    type Plaintext: Wire + Clone;

    // Encrypt a message under the public parameters and tag.
    fn encrypt(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        pt: &Self::Plaintext,
        rng: &mut dyn RngCore,
    ) -> Result<Self::Ciphertext, Error>;

    // Produce a partial release (e.g. partial signature).
    fn partial_release(
        pp: &Self::PublicParams,
        sk_i: &Self::PartySecret,
        tag: &Self::ReleaseTag,
    ) -> Result<Self::PartialWitness, Error>;

    // Verify a partial release against the sender's public share.
    fn verify_partial(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        from: PartyId,
        w: &Self::PartialWitness,
    ) -> Result<(), Error>;

    // Combine t partials into a full witness.
    fn combine(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        partials: &[(PartyId, Self::PartialWitness)],
    ) -> Result<Self::FullWitness, Error>;

    // Decrypt using the full witness.
    fn decrypt(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        ct: &Self::Ciphertext,
        witness: &Self::FullWitness,
    ) -> Result<Self::Plaintext, Error>;
}

pub trait MempoolEncryptionScheme:
    SetupProtocol
    + ThresholdRelease<
        PublicParams = <Self as SetupProtocol>::PublicParams,
        PartySecret = <Self as SetupProtocol>::PartySecret,
    >
{
}
