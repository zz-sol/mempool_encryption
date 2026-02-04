//! BLS12-381 helpers (blstrs): hash-to-curve, pairing, serialization.

use std::io::Cursor;

use blstrs::{Compress, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use ff::Field;
use group::Curve;

use crate::types::{Error, PartyId};

pub type Fr = Scalar;
pub type G1 = G1Projective;
pub type G2 = G2Projective;
pub type Target = Gt;

pub fn hash_to_g1(msg: &[u8], dst: &[u8]) -> G1 {
    // Hash-to-curve for BLS signatures.
    G1Projective::hash_to_curve(msg, dst, &[])
}

pub fn pairing(g1: &G1, g2: &G2) -> Target {
    // Standard BLS12-381 pairing.
    blstrs::pairing(&g1.to_affine(), &g2.to_affine())
}

pub fn scalar_from_id(id: PartyId) -> Result<Fr, Error> {
    // Party IDs are mapped to field elements via integer embedding.
    if id == 0 {
        return Err(Error::InvalidParams);
    }
    Ok(Fr::from(id as u64))
}

pub fn scalar_random<R: rand_core::RngCore + ?Sized>(rng: &mut R) -> Fr {
    // Sample a uniform scalar.
    Fr::random(rng)
}

pub fn scalar_inv(x: &Fr) -> Result<Fr, Error> {
    // Invert a scalar (error if zero).
    Option::from(x.invert()).ok_or(Error::InvalidParams)
}

pub fn scalar_to_bytes(s: &Fr) -> [u8; 32] {
    s.to_bytes_be()
}

pub fn scalar_from_bytes(bytes: &[u8]) -> Result<Fr, Error> {
    if bytes.len() != 32 {
        return Err(Error::InvalidEncoding);
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(bytes);
    Option::<Fr>::from(Fr::from_bytes_be(&raw)).ok_or(Error::InvalidEncoding)
}

pub fn g1_to_bytes(p: &G1) -> [u8; 48] {
    // Compressed encoding for G1.
    p.to_affine().to_compressed()
}

pub fn g1_from_bytes(bytes: &[u8]) -> Result<G1, Error> {
    // Decode compressed G1, rejecting invalid points.
    if bytes.len() != 48 {
        return Err(Error::InvalidEncoding);
    }
    let mut raw = [0u8; 48];
    raw.copy_from_slice(bytes);
    let affine =
        Option::<G1Affine>::from(G1Affine::from_compressed(&raw)).ok_or(Error::InvalidEncoding)?;
    Ok(affine.into())
}

pub fn g2_to_bytes(p: &G2) -> [u8; 96] {
    // Compressed encoding for G2.
    p.to_affine().to_compressed()
}

pub fn g2_from_bytes(bytes: &[u8]) -> Result<G2, Error> {
    // Decode compressed G2, rejecting invalid points.
    if bytes.len() != 96 {
        return Err(Error::InvalidEncoding);
    }
    let mut raw = [0u8; 96];
    raw.copy_from_slice(bytes);
    let affine =
        Option::<G2Affine>::from(G2Affine::from_compressed(&raw)).ok_or(Error::InvalidEncoding)?;
    Ok(affine.into())
}

pub fn gt_to_bytes(t: &Target) -> Vec<u8> {
    // Compressed GT encoding for transcript/KEM inputs.
    let mut bytes = Vec::with_capacity(288);
    t.write_compressed(&mut bytes)
        .map_err(|_| Error::InvalidEncoding)
        .expect("in-memory serialization should not fail");
    bytes
}

pub fn gt_from_bytes(bytes: &[u8]) -> Result<Target, Error> {
    // Decode compressed GT.
    let mut cursor = Cursor::new(bytes);
    Target::read_compressed(&mut cursor).map_err(|_| Error::InvalidEncoding)
}
