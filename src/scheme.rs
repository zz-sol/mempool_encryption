use rand_core::RngCore;

use crate::types::{Error, Params, PartyId, PartyInfo, Wire};

pub trait SetupProtocol {
    type PublicParams: Wire + Clone;
    type PartySecret: Wire + Clone;
    type SetupMessage: Wire + Clone;
    type SetupState;

    fn init(params: Params, me: PartyInfo) -> Self::SetupState;

    fn handle_message(
        state: &mut Self::SetupState,
        from: PartyId,
        msg: Self::SetupMessage,
    ) -> Result<Vec<(PartyId, Self::SetupMessage)>, Error>;

    fn begin_round(
        state: &mut Self::SetupState,
    ) -> Result<Vec<(PartyId, Self::SetupMessage)>, Error> {
        let _ = state;
        Ok(vec![])
    }

    fn finalize(state: Self::SetupState) -> Result<(Self::PublicParams, Self::PartySecret), Error>;
}

pub trait ThresholdRelease {
    type PublicParams: Wire + Clone;
    type PartySecret: Wire + Clone;
    type Ciphertext: Wire + Clone;
    type ReleaseTag: Wire + Clone;
    type PartialWitness: Wire + Clone;
    type FullWitness: Wire + Clone;
    type Plaintext: Wire + Clone;

    fn encrypt(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        pt: &Self::Plaintext,
        rng: &mut dyn RngCore,
    ) -> Result<Self::Ciphertext, Error>;

    fn partial_release(
        pp: &Self::PublicParams,
        sk_i: &Self::PartySecret,
        tag: &Self::ReleaseTag,
    ) -> Result<Self::PartialWitness, Error>;

    fn verify_partial(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        from: PartyId,
        w: &Self::PartialWitness,
    ) -> Result<(), Error>;

    fn combine(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        partials: &[(PartyId, Self::PartialWitness)],
    ) -> Result<Self::FullWitness, Error>;

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
