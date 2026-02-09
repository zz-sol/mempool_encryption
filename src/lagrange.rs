//! Lagrange coefficient helpers for threshold combining.

use blstrs::Scalar;
use ff::Field;
use group::Group;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::bls::scalar_from_id;
use crate::types::{Error, PartyId};

pub fn lagrange_coefficients_at_zero(ids: &[PartyId]) -> Result<Vec<Scalar>, Error> {
    // Compute Lagrange coefficients for interpolation at x=0.
    if ids.is_empty() {
        return Err(Error::InvalidParams);
    }
    let mut coeffs = Vec::with_capacity(ids.len());
    for (i, id_i) in ids.iter().enumerate() {
        let x_i = scalar_from_id(*id_i)?;
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for (j, id_j) in ids.iter().enumerate() {
            if i == j {
                continue;
            }
            let x_j = scalar_from_id(*id_j)?;
            num *= -x_j;
            den *= x_i - x_j;
        }
        let den_inv = Option::<Scalar>::from(den.invert()).ok_or(Error::InvalidParams)?;
        coeffs.push(num * den_inv);
    }
    Ok(coeffs)
}

pub fn combine_g1_at_zero(
    ids: &[PartyId],
    values: &[blstrs::G1Projective],
) -> Result<blstrs::G1Projective, Error> {
    // Interpolate group elements at x=0 using Lagrange coefficients.
    if ids.len() != values.len() {
        return Err(Error::InvalidParams);
    }
    let coeffs = lagrange_coefficients_at_zero(ids)?;

    #[cfg(feature = "parallel")]
    let acc = coeffs
        .par_iter()
        .zip(values.par_iter())
        .map(|(coeff, value)| *value * *coeff)
        .reduce(blstrs::G1Projective::identity, |a, b| a + b);

    #[cfg(not(feature = "parallel"))]
    let acc = {
        let mut acc = blstrs::G1Projective::identity();
        for (coeff, value) in coeffs.iter().zip(values.iter()) {
            acc += *value * *coeff;
        }
        acc
    };

    Ok(acc)
}

pub fn combine_g2_at_zero(
    ids: &[PartyId],
    values: &[blstrs::G2Projective],
) -> Result<blstrs::G2Projective, Error> {
    // Same as above, but for G2.
    if ids.len() != values.len() {
        return Err(Error::InvalidParams);
    }
    let coeffs = lagrange_coefficients_at_zero(ids)?;

    #[cfg(feature = "parallel")]
    let acc = coeffs
        .par_iter()
        .zip(values.par_iter())
        .map(|(coeff, value)| *value * *coeff)
        .reduce(blstrs::G2Projective::identity, |a, b| a + b);

    #[cfg(not(feature = "parallel"))]
    let acc = {
        let mut acc = blstrs::G2Projective::identity();
        for (coeff, value) in coeffs.iter().zip(values.iter()) {
            acc += *value * *coeff;
        }
        acc
    };

    Ok(acc)
}
