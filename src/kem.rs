use rand_core::RngCore;

use blstrs::{G1Projective, G2Projective};
use group::Group;

use crate::aead;
use crate::bls::{g1_from_bytes, g1_to_bytes, g2_from_bytes, g2_to_bytes, gt_to_bytes, hash_to_g1, pairing, scalar_random};
use crate::dkg::{BlsDkgScheme, DkgPartySecret, DkgPublicParams};
use crate::encoding::{dec_bytes, enc_bytes, enc_tuple};
use crate::kdf::{hkdf_expand, hkdf_extract};
use crate::lagrange::combine_g1_at_zero;
use crate::scheme::ThresholdRelease;
use crate::types::{Error, PartyId, Wire};

const SALT_KEM: &[u8] = b"MEMP-ENC-KEM-V1";
const DST_KDF: &[u8] = b"MEMP-ENC-KDF-V1";

#[derive(Clone, Debug)]
pub struct BlsCiphertext {
    pub tag: Vec<u8>,
    pub u: G2Projective,
    pub ck: [u8; 32],
    pub nonce: [u8; 12],
    pub cm: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct BlsTag(pub Vec<u8>);

#[derive(Clone, Debug)]
pub struct BlsPlaintext(pub Vec<u8>);

#[derive(Clone, Debug)]
pub struct BlsPartialSig(pub G1Projective);

#[derive(Clone, Debug)]
pub struct BlsFullSig(pub G1Projective);

impl Wire for BlsTag {
    fn encode(&self) -> Vec<u8> {
        enc_bytes(&self.0)
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (data, rest) = dec_bytes(bytes)?;
        if !rest.is_empty() {
            return Err(Error::InvalidEncoding);
        }
        Ok(BlsTag(data))
    }
}

impl Wire for BlsPlaintext {
    fn encode(&self) -> Vec<u8> {
        enc_bytes(&self.0)
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (data, rest) = dec_bytes(bytes)?;
        if !rest.is_empty() {
            return Err(Error::InvalidEncoding);
        }
        Ok(BlsPlaintext(data))
    }
}

impl Wire for BlsCiphertext {
    fn encode(&self) -> Vec<u8> {
        let u_bytes = g2_to_bytes(&self.u);
        let mut out = Vec::new();
        out.extend_from_slice(&enc_bytes(&self.tag));
        out.extend_from_slice(&enc_bytes(&u_bytes));
        out.extend_from_slice(&enc_bytes(&self.ck));
        out.extend_from_slice(&enc_bytes(&self.nonce));
        out.extend_from_slice(&enc_bytes(&self.cm));
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (tag, rest) = dec_bytes(bytes)?;
        let (u_raw, rest) = dec_bytes(rest)?;
        let (ck_raw, rest) = dec_bytes(rest)?;
        let (nonce_raw, rest) = dec_bytes(rest)?;
        let (cm, rest) = dec_bytes(rest)?;
        if !rest.is_empty() {
            return Err(Error::InvalidEncoding);
        }
        if ck_raw.len() != 32 || nonce_raw.len() != 12 {
            return Err(Error::InvalidEncoding);
        }
        let u = g2_from_bytes(&u_raw)?;
        let mut ck = [0u8; 32];
        ck.copy_from_slice(&ck_raw);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_raw);
        Ok(BlsCiphertext { tag, u, ck, nonce, cm })
    }
}

impl Wire for BlsPartialSig {
    fn encode(&self) -> Vec<u8> {
        g1_to_bytes(&self.0).to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Ok(BlsPartialSig(g1_from_bytes(bytes)?))
    }
}

impl Wire for BlsFullSig {
    fn encode(&self) -> Vec<u8> {
        g1_to_bytes(&self.0).to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Ok(BlsFullSig(g1_from_bytes(bytes)?))
    }
}

impl ThresholdRelease for BlsDkgScheme {
    type PublicParams = DkgPublicParams;
    type PartySecret = DkgPartySecret;
    type Ciphertext = BlsCiphertext;
    type ReleaseTag = BlsTag;
    type PartialWitness = BlsPartialSig;
    type FullWitness = BlsFullSig;
    type Plaintext = BlsPlaintext;

    fn encrypt(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        pt: &Self::Plaintext,
        rng: &mut dyn RngCore,
    ) -> Result<Self::Ciphertext, Error> {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let r = scalar_random(rng);
        let u = G2Projective::generator() * r;
        let h = hash_to_g1(&tag.0, b"MEMP-ENC-SIG-V1");
        let w = pairing(&h, &pp.pk) * r;
        let prk = hkdf_extract(SALT_KEM, &enc_bytes(&gt_to_bytes(&w)));
        let ad = enc_tuple(&[&tag.0, &g2_to_bytes(&u), &g2_to_bytes(&pp.pk)]);
        let mut info = Vec::with_capacity(DST_KDF.len() + ad.len());
        info.extend_from_slice(DST_KDF);
        info.extend_from_slice(&ad);
        let k_prime = hkdf_expand(&prk, &info, 32)?;
        let mut ck = [0u8; 32];
        for i in 0..32 {
            ck[i] = key[i] ^ k_prime[i];
        }
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);
        let cm = aead::encrypt(&key, &nonce, &pt.0, &ad)?;
        Ok(BlsCiphertext {
            tag: tag.0.clone(),
            u,
            ck,
            nonce,
            cm,
        })
    }

    fn partial_release(
        _pp: &Self::PublicParams,
        sk_i: &Self::PartySecret,
        tag: &Self::ReleaseTag,
    ) -> Result<Self::PartialWitness, Error> {
        let h = hash_to_g1(&tag.0, b"MEMP-ENC-SIG-V1");
        Ok(BlsPartialSig(h * sk_i.share))
    }

    fn verify_partial(
        pp: &Self::PublicParams,
        tag: &Self::ReleaseTag,
        from: PartyId,
        w: &Self::PartialWitness,
    ) -> Result<(), Error> {
        let h = hash_to_g1(&tag.0, b"MEMP-ENC-SIG-V1");
        let pk_i = pp
            .pk_shares
            .iter()
            .find(|(id, _)| *id == from)
            .map(|(_, pk)| pk)
            .ok_or(Error::InvalidShare)?;
        let left = pairing(&w.0, &G2Projective::generator());
        let right = pairing(&h, pk_i);
        if left == right {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    fn combine(
        _pp: &Self::PublicParams,
        _tag: &Self::ReleaseTag,
        partials: &[(PartyId, Self::PartialWitness)],
    ) -> Result<Self::FullWitness, Error> {
        let ids: Vec<PartyId> = partials.iter().map(|(id, _)| *id).collect();
        let sigs: Vec<G1Projective> = partials.iter().map(|(_, sig)| sig.0).collect();
        Ok(BlsFullSig(combine_g1_at_zero(&ids, &sigs)?))
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
        let w = pairing(&witness.0, &ct.u);
        let prk = hkdf_extract(SALT_KEM, &enc_bytes(&gt_to_bytes(&w)));
        let ad = enc_tuple(&[&ct.tag, &g2_to_bytes(&ct.u), &g2_to_bytes(&pp.pk)]);
        let mut info = Vec::with_capacity(DST_KDF.len() + ad.len());
        info.extend_from_slice(DST_KDF);
        info.extend_from_slice(&ad);
        let k_prime = hkdf_expand(&prk, &info, 32)?;
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = ct.ck[i] ^ k_prime[i];
        }
        let pt = aead::decrypt(&key, &ct.nonce, &ct.cm, &ad)?;
        Ok(BlsPlaintext(pt))
    }
}
