//! Adapter that wraps the TESS silent setup scheme behind the mempool traits.

use rand_core::RngCore;
use serde::{Deserialize, Serialize};

use tess::{
    AggregateKey, Ciphertext, PairingEngine, PartialDecryption, PublicKey, SecretKey,
    SilentThresholdScheme, ThresholdEncryption,
};

use crate::encoding::{dec_bytes, enc_bytes};
use crate::scheme::{SetupProtocol, ThresholdRelease};
use crate::types::{Error, Params, PartyId, PartyInfo, Wire, validate_params};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TessPublicParams {
    pub params: tess::Params<PairingEngine>,
    pub agg_key: AggregateKey<PairingEngine>,
    pub parties: usize,
    pub threshold: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TessPartySecret {
    pub id: PartyId,
    pub secret: SecretKey<PairingEngine>,
}

#[derive(Clone, Debug, Default)]
pub struct TessSetupConfig {
    pub params: Option<tess::Params<PairingEngine>>,
    pub public_keys: Option<Vec<PublicKey<PairingEngine>>>,
    pub secret_key: Option<SecretKey<PairingEngine>>,
}

impl TessSetupConfig {
    pub fn with_params_and_keys(
        params: tess::Params<PairingEngine>,
        public_keys: Vec<PublicKey<PairingEngine>>,
        secret_key: SecretKey<PairingEngine>,
    ) -> Self {
        Self {
            params: Some(params),
            public_keys: Some(public_keys),
            secret_key: Some(secret_key),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TessCiphertext {
    pub tag: Vec<u8>,
    pub inner: Ciphertext<PairingEngine>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TessPartial(pub PartialDecryption<PairingEngine>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TessFullWitness {
    pub partials: Vec<PartialDecryption<PairingEngine>>,
}

#[derive(Clone, Debug)]
pub struct TessTag(pub Vec<u8>);

#[derive(Clone, Debug)]
pub struct TessPlaintext(pub Vec<u8>);

pub struct TessScheme;

pub struct TessSetupState {
    result: Result<(TessPublicParams, TessPartySecret), Error>,
}

impl SetupProtocol for TessScheme {
    type PublicParams = TessPublicParams;
    type PartySecret = TessPartySecret;
    type SetupMessage = Vec<u8>;
    type SetupState = TessSetupState;
    type SetupConfig = TessSetupConfig;

    fn init_with(params: Params, me: PartyInfo, config: Self::SetupConfig) -> Self::SetupState {
        let result = (|| -> Result<(TessPublicParams, TessPartySecret), Error> {
            validate_params(params)?;
            if me.id == 0 {
                return Err(Error::InvalidParams);
            }
            let parties = params.n as usize;
            let threshold = params.t as usize;

            let scheme = SilentThresholdScheme::<PairingEngine>::new();
            let TessSetupConfig {
                params: config_params,
                public_keys,
                secret_key,
            } = config;

            if config_params.is_none() || public_keys.is_none() || secret_key.is_none() {
                return Err(Error::InvalidParams);
            }
            if secret_key.is_some() ^ public_keys.is_some() {
                return Err(Error::InvalidParams);
            }

            let tess_params = config_params.expect("checked");
            let secret_key = secret_key.expect("checked");
            let public_keys = public_keys.expect("checked");

            if public_keys.len() != parties {
                return Err(Error::InvalidParams);
            }
            if secret_key.participant_id != party_to_index(me.id)? {
                return Err(Error::InvalidParams);
            }

            let agg_key = scheme
                .aggregate_public_key(&public_keys, &tess_params, parties)
                .map_err(map_tess_error)?;

            Ok((
                TessPublicParams {
                    params: tess_params,
                    agg_key,
                    parties,
                    threshold,
                },
                TessPartySecret {
                    id: me.id,
                    secret: secret_key,
                },
            ))
        })();

        TessSetupState { result }
    }

    fn default_config() -> Self::SetupConfig {
        TessSetupConfig::default()
    }

    fn handle_message(
        _state: &mut Self::SetupState,
        _from: PartyId,
        _msg: Self::SetupMessage,
    ) -> Result<Vec<(PartyId, Self::SetupMessage)>, Error> {
        Ok(vec![])
    }

    fn finalize(state: Self::SetupState) -> Result<(Self::PublicParams, Self::PartySecret), Error> {
        state.result
    }
}

impl ThresholdRelease for TessScheme {
    type PublicParams = TessPublicParams;
    type PartySecret = TessPartySecret;
    type Ciphertext = TessCiphertext;
    type ReleaseTag = TessTag;
    type PartialWitness = TessPartial;
    type FullWitness = TessFullWitness;
    type Plaintext = TessPlaintext;

    fn encrypt(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        pt: &Self::Plaintext,
        rng: &mut dyn RngCore,
    ) -> Result<Self::Ciphertext, Error> {
        let scheme = SilentThresholdScheme::<PairingEngine>::new();
        let inner = scheme
            .encrypt(rng, &pp.agg_key, &pp.params, pp.threshold, &pt.0)
            .map_err(map_tess_error)?;
        Ok(TessCiphertext {
            tag: tag.0.clone(),
            inner,
        })
    }

    fn partial_release(
        _pp: &Self::PublicParams,
        sk_i: &Self::PartySecret,
        _tag: &Self::ReleaseTag,
        ct: &Self::Ciphertext,
    ) -> Result<Self::PartialWitness, Error> {
        let scheme = SilentThresholdScheme::<PairingEngine>::new();
        let partial = scheme
            .partial_decrypt(&sk_i.secret, &ct.inner)
            .map_err(map_tess_error)?;
        Ok(TessPartial(partial))
    }

    fn verify_partial(
        _pp: &Self::PublicParams,
        _tag: &Self::ReleaseTag,
        _ct: &Self::Ciphertext,
        from: PartyId,
        w: &Self::PartialWitness,
    ) -> Result<(), Error> {
        if w.0.participant_id != party_to_index(from)? {
            return Err(Error::InvalidShare);
        }
        Ok(())
    }

    fn combine(
        _pp: &Self::PublicParams,
        _tag: &Self::ReleaseTag,
        _ct: &Self::Ciphertext,
        partials: &[(PartyId, Self::PartialWitness)],
    ) -> Result<Self::FullWitness, Error> {
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::with_capacity(partials.len());
        for (id, w) in partials.iter() {
            let idx = party_to_index(*id)?;
            if w.0.participant_id != idx {
                return Err(Error::InvalidShare);
            }
            if !seen.insert(idx) {
                return Err(Error::InvalidParams);
            }
            out.push(w.0.clone());
        }
        Ok(TessFullWitness { partials: out })
    }

    fn decrypt(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        ct: &Self::Ciphertext,
        witness: &Self::FullWitness,
    ) -> Result<Self::Plaintext, Error> {
        if ct.tag != tag.0 {
            return Err(Error::InvalidParams);
        }
        let scheme = SilentThresholdScheme::<PairingEngine>::new();
        let selector = build_selector(pp.parties, &witness.partials)?;
        let res = scheme
            .aggregate_decrypt(&ct.inner, &witness.partials, &selector, &pp.agg_key)
            .map_err(map_tess_error)?;
        let pt = res.plaintext.ok_or(Error::DecryptionFailed)?;
        Ok(TessPlaintext(pt))
    }
}

impl Wire for TessTag {
    fn encode(&self) -> Vec<u8> {
        enc_bytes(&self.0).expect("length must fit u32")
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (data, rest) = dec_bytes(bytes)?;
        if !rest.is_empty() {
            return Err(Error::InvalidEncoding);
        }
        Ok(TessTag(data))
    }
}

impl Wire for TessPlaintext {
    fn encode(&self) -> Vec<u8> {
        enc_bytes(&self.0).expect("length must fit u32")
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (data, rest) = dec_bytes(bytes)?;
        if !rest.is_empty() {
            return Err(Error::InvalidEncoding);
        }
        Ok(TessPlaintext(data))
    }
}

impl Wire for TessPublicParams {
    fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serde_json")
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        serde_json::from_slice(bytes).map_err(|_| Error::InvalidEncoding)
    }
}

impl Wire for TessPartySecret {
    fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serde_json")
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        serde_json::from_slice(bytes).map_err(|_| Error::InvalidEncoding)
    }
}

impl Wire for TessCiphertext {
    fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serde_json")
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        serde_json::from_slice(bytes).map_err(|_| Error::InvalidEncoding)
    }
}

impl Wire for TessPartial {
    fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serde_json")
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        serde_json::from_slice(bytes).map_err(|_| Error::InvalidEncoding)
    }
}

impl Wire for TessFullWitness {
    fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serde_json")
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        serde_json::from_slice(bytes).map_err(|_| Error::InvalidEncoding)
    }
}

fn party_to_index(id: PartyId) -> Result<usize, Error> {
    if id == 0 {
        return Err(Error::InvalidParams);
    }
    Ok((id - 1) as usize)
}

fn build_selector(
    parties: usize,
    partials: &[PartialDecryption<PairingEngine>],
) -> Result<Vec<bool>, Error> {
    let mut selector = vec![false; parties];
    for p in partials {
        if p.participant_id >= parties {
            return Err(Error::InvalidParams);
        }
        selector[p.participant_id] = true;
    }
    if parties == 0 || !selector[0] {
        return Err(Error::InvalidParams);
    }
    Ok(selector)
}

fn map_tess_error(err: tess::Error) -> Error {
    match err {
        tess::Error::InvalidConfig(_) => Error::InvalidParams,
        tess::Error::MalformedInput(_) => Error::InvalidEncoding,
        tess::Error::NotEnoughShares { .. } => Error::InvalidShare,
        tess::Error::SelectorMismatch { .. } => Error::InvalidParams,
        tess::Error::Backend(_) => Error::CryptoError,
    }
}
