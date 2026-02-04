use std::collections::{HashMap, HashSet};

use blstrs::{G2Projective, Scalar};
use ff::Field;
use group::Group;

use crate::bls::{g2_from_bytes, g2_to_bytes, scalar_from_id, scalar_random};
use crate::encoding::{dec_bytes, enc_bytes, enc_len};
use crate::lagrange::combine_g2_at_zero;
use crate::scheme::SetupProtocol;
use crate::types::{Error, Params, PartyId, PartyInfo, Wire, validate_params};

#[derive(Clone, Debug)]
pub struct DkgPublicParams {
    pub pk: G2Projective,
    pub pk_shares: Vec<(PartyId, G2Projective)>,
}

#[derive(Clone, Debug)]
pub struct DkgPartySecret {
    pub id: PartyId,
    pub share: Scalar,
}

#[derive(Clone, Debug)]
pub struct DkgCommitment {
    pub from: PartyId,
    pub coeffs: Vec<G2Projective>,
}

#[derive(Clone, Debug)]
pub struct DkgShare {
    pub from: PartyId,
    pub to: PartyId,
    pub f_i: Scalar,
    pub r_i: Scalar,
}

#[derive(Clone, Debug)]
pub struct DkgComplaint {
    pub from: PartyId,
    pub against: PartyId,
}

#[derive(Clone, Debug)]
pub enum DkgMessage {
    Commitment(DkgCommitment),
    Share(DkgShare),
    Complaint(DkgComplaint),
}

pub struct DkgState {
    params: Params,
    me: PartyInfo,
    valid: bool,
    a_coeffs: Vec<Scalar>,
    b_coeffs: Vec<Scalar>,
    commitments: HashMap<PartyId, Vec<G2Projective>>,
    shares: HashMap<PartyId, (Scalar, Scalar)>,
    complaints: HashSet<PartyId>,
    complaints_from: HashSet<PartyId>,
}

impl DkgState {
    pub fn new(params: Params, me: PartyInfo) -> Self {
        let valid = validate_params(params).is_ok();
        let mut rng = rand_core::OsRng;
        let t = if valid { params.t as usize } else { 0 };
        let mut a_coeffs = Vec::with_capacity(t);
        let mut b_coeffs = Vec::with_capacity(t);
        for _ in 0..t {
            a_coeffs.push(scalar_random(&mut rng));
            b_coeffs.push(scalar_random(&mut rng));
        }
        let mut state = Self {
            params,
            me,
            valid,
            a_coeffs,
            b_coeffs,
            commitments: HashMap::new(),
            shares: HashMap::new(),
            complaints: HashSet::new(),
            complaints_from: HashSet::new(),
        };
        if state.valid {
            state.insert_self_share();
        }
        state
    }

    pub fn initial_messages(&self) -> Result<Vec<(PartyId, DkgMessage)>, Error> {
        if !self.valid {
            return Err(Error::InvalidParams);
        }
        let mut out = Vec::new();
        let h2 = hash_to_g2(b"MEMP-ENC-H2");
        let g2 = G2Projective::generator();

        let mut coeffs = Vec::with_capacity(self.a_coeffs.len());
        for (a, b) in self.a_coeffs.iter().zip(self.b_coeffs.iter()) {
            let c = g2 * a + h2 * b;
            coeffs.push(c);
        }
        let commit_msg = DkgMessage::Commitment(DkgCommitment {
            from: self.me.id,
            coeffs: coeffs.clone(),
        });
        for to in 1..=self.params.n {
            out.push((to, commit_msg.clone()));
        }

        for to in 1..=self.params.n {
            let x = scalar_from_id(to)?;
            let f_i = eval_poly(&self.a_coeffs, &x);
            let r_i = eval_poly(&self.b_coeffs, &x);
            out.push((
                to,
                DkgMessage::Share(DkgShare {
                    from: self.me.id,
                    to,
                    f_i,
                    r_i,
                }),
            ));
        }
        Ok(out)
    }

    fn insert_self_share(&mut self) {
        let h2 = hash_to_g2(b"MEMP-ENC-H2");
        let g2 = G2Projective::generator();
        let mut coeffs = Vec::with_capacity(self.a_coeffs.len());
        for (a, b) in self.a_coeffs.iter().zip(self.b_coeffs.iter()) {
            let c = g2 * a + h2 * b;
            coeffs.push(c);
        }
        self.commitments.insert(self.me.id, coeffs);
        if let Ok(x) = scalar_from_id(self.me.id) {
            let f_i = eval_poly(&self.a_coeffs, &x);
            let r_i = eval_poly(&self.b_coeffs, &x);
            self.shares.insert(self.me.id, (f_i, r_i));
        }
    }

    pub fn handle_message(
        &mut self,
        from: PartyId,
        msg: DkgMessage,
    ) -> Result<Vec<(PartyId, DkgMessage)>, Error> {
        if !self.valid {
            return Err(Error::InvalidParams);
        }
        match msg {
            DkgMessage::Commitment(c) => {
                if c.from != from {
                    return Err(Error::InvalidMessage);
                }
                if c.coeffs.len() != self.params.t as usize {
                    return Err(Error::InvalidMessage);
                }
                self.commitments.insert(from, c.coeffs);
            }
            DkgMessage::Share(s) => {
                if s.from != from || s.to != self.me.id {
                    return Err(Error::InvalidMessage);
                }
                self.shares.insert(from, (s.f_i, s.r_i));
            }
            DkgMessage::Complaint(c) => {
                if c.from != from {
                    return Err(Error::InvalidMessage);
                }
                self.complaints_from.insert(c.against);
            }
        }
        Ok(vec![])
    }

    pub fn verify_shares(&mut self) -> Result<Vec<(PartyId, DkgMessage)>, Error> {
        if !self.valid {
            return Err(Error::InvalidParams);
        }
        let mut out = Vec::new();
        let h2 = hash_to_g2(b"MEMP-ENC-H2");
        let g2 = G2Projective::generator();
        let x_i = scalar_from_id(self.me.id)?;

        for dealer in 1..=self.params.n {
            let coeffs = match self.commitments.get(&dealer) {
                Some(c) => c,
                None => {
                    self.complaints.insert(dealer);
                    for to in 1..=self.params.n {
                        out.push((
                            to,
                            DkgMessage::Complaint(DkgComplaint {
                                from: self.me.id,
                                against: dealer,
                            }),
                        ));
                    }
                    continue;
                }
            };
            let (f_i, r_i) = match self.shares.get(&dealer) {
                Some(v) => v,
                None => {
                    self.complaints.insert(dealer);
                    for to in 1..=self.params.n {
                        out.push((
                            to,
                            DkgMessage::Complaint(DkgComplaint {
                                from: self.me.id,
                                against: dealer,
                            }),
                        ));
                    }
                    continue;
                }
            };

            let lhs = g2 * f_i + h2 * r_i;
            let mut rhs = G2Projective::identity();
            let mut power = Scalar::ONE;
            for c_k in coeffs.iter() {
                rhs += *c_k * power;
                power *= x_i;
            }
            if lhs != rhs {
                self.complaints.insert(dealer);
                for to in 1..=self.params.n {
                    out.push((
                        to,
                        DkgMessage::Complaint(DkgComplaint {
                            from: self.me.id,
                            against: dealer,
                        }),
                    ));
                }
            }
        }
        Ok(out)
    }

    pub fn finalize(self) -> Result<(DkgPublicParams, DkgPartySecret), Error> {
        if !self.valid {
            return Err(Error::InvalidParams);
        }
        let mut qual = Vec::new();
        for dealer in 1..=self.params.n {
            if self.complaints.contains(&dealer) || self.complaints_from.contains(&dealer) {
                continue;
            }
            if self.commitments.contains_key(&dealer) && self.shares.contains_key(&dealer) {
                qual.push(dealer);
            }
        }
        if qual.len() < self.params.t as usize {
            return Err(Error::InvalidParams);
        }

        let mut share = Scalar::ZERO;
        for dealer in qual.iter() {
            let (f_i, _) = self.shares.get(dealer).ok_or(Error::InvalidShare)?;
            share += f_i;
        }

        let pk = G2Projective::identity();
        let mut pk_shares = Vec::with_capacity(1);
        // NOTE: With Pedersen commitments, pk cannot be derived from commitments
        // alone because of the blinding term. It must be recomputed from pk_shares
        // once enough shares are collected externally.
        let pk_i = G2Projective::generator() * share;
        pk_shares.push((self.me.id, pk_i));

        Ok((
            DkgPublicParams { pk, pk_shares },
            DkgPartySecret {
                id: self.me.id,
                share,
            },
        ))
    }
}

pub struct BlsDkgScheme;

impl SetupProtocol for BlsDkgScheme {
    type PublicParams = DkgPublicParams;
    type PartySecret = DkgPartySecret;
    type SetupMessage = DkgMessage;
    type SetupState = DkgState;

    fn init(params: Params, me: PartyInfo) -> Self::SetupState {
        DkgState::new(params, me)
    }

    fn handle_message(
        state: &mut Self::SetupState,
        from: PartyId,
        msg: Self::SetupMessage,
    ) -> Result<Vec<(PartyId, Self::SetupMessage)>, Error> {
        state.handle_message(from, msg)
    }

    fn begin_round(
        state: &mut Self::SetupState,
    ) -> Result<Vec<(PartyId, Self::SetupMessage)>, Error> {
        state.initial_messages()
    }

    fn finalize(state: Self::SetupState) -> Result<(Self::PublicParams, Self::PartySecret), Error> {
        state.finalize()
    }
}

fn eval_poly(coeffs: &[Scalar], x: &Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    for coeff in coeffs.iter().rev() {
        acc *= x;
        acc += coeff;
    }
    acc
}

#[allow(dead_code)]
fn _eval_commitment(coeffs: &[G2Projective], x: &Scalar) -> G2Projective {
    let mut acc = G2Projective::identity();
    let mut power = Scalar::ONE;
    for c_k in coeffs.iter() {
        acc += *c_k * power;
        power *= x;
    }
    acc
}

impl Wire for DkgCommitment {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.from.to_be_bytes());
        out.extend_from_slice(&enc_len(self.coeffs.len()).expect("length must fit u32"));
        for c in self.coeffs.iter() {
            out.extend_from_slice(&g2_to_bytes(c));
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 8 {
            return Err(Error::InvalidEncoding);
        }
        let mut from_bytes = [0u8; 4];
        from_bytes.copy_from_slice(&bytes[0..4]);
        let from = u32::from_be_bytes(from_bytes);
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[4..8]);
        let n = u32::from_be_bytes(len_bytes) as usize;
        let mut offset = 8;
        let mut coeffs = Vec::with_capacity(n);
        for _ in 0..n {
            let end = offset + 96;
            if end > bytes.len() {
                return Err(Error::InvalidEncoding);
            }
            coeffs.push(g2_from_bytes(&bytes[offset..end])?);
            offset = end;
        }
        if offset != bytes.len() {
            return Err(Error::InvalidEncoding);
        }
        Ok(DkgCommitment { from, coeffs })
    }
}

impl Wire for DkgShare {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 4 + 32 + 32);
        out.extend_from_slice(&self.from.to_be_bytes());
        out.extend_from_slice(&self.to.to_be_bytes());
        out.extend_from_slice(&self.f_i.to_bytes_be());
        out.extend_from_slice(&self.r_i.to_bytes_be());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 4 + 4 + 32 + 32 {
            return Err(Error::InvalidEncoding);
        }
        let mut from_bytes = [0u8; 4];
        let mut to_bytes = [0u8; 4];
        from_bytes.copy_from_slice(&bytes[0..4]);
        to_bytes.copy_from_slice(&bytes[4..8]);
        let from = u32::from_be_bytes(from_bytes);
        let to = u32::from_be_bytes(to_bytes);
        let f_i = Option::<Scalar>::from(Scalar::from_bytes_be(
            &bytes[8..40]
                .try_into()
                .map_err(|_| Error::InvalidEncoding)?,
        ))
        .ok_or(Error::InvalidEncoding)?;
        let r_i = Option::<Scalar>::from(Scalar::from_bytes_be(
            &bytes[40..72]
                .try_into()
                .map_err(|_| Error::InvalidEncoding)?,
        ))
        .ok_or(Error::InvalidEncoding)?;
        Ok(DkgShare { from, to, f_i, r_i })
    }
}

impl Wire for DkgComplaint {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&self.from.to_be_bytes());
        out.extend_from_slice(&self.against.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 8 {
            return Err(Error::InvalidEncoding);
        }
        let mut from_bytes = [0u8; 4];
        let mut against_bytes = [0u8; 4];
        from_bytes.copy_from_slice(&bytes[0..4]);
        against_bytes.copy_from_slice(&bytes[4..8]);
        Ok(DkgComplaint {
            from: u32::from_be_bytes(from_bytes),
            against: u32::from_be_bytes(against_bytes),
        })
    }
}

impl Wire for DkgMessage {
    fn encode(&self) -> Vec<u8> {
        match self {
            DkgMessage::Commitment(c) => {
                let mut out = vec![0u8];
                let body = c.encode();
                out.extend_from_slice(&enc_bytes(&body).expect("length must fit u32"));
                out
            }
            DkgMessage::Share(s) => {
                let mut out = vec![1u8];
                let body = s.encode();
                out.extend_from_slice(&enc_bytes(&body).expect("length must fit u32"));
                out
            }
            DkgMessage::Complaint(c) => {
                let mut out = vec![2u8];
                let body = c.encode();
                out.extend_from_slice(&enc_bytes(&body).expect("length must fit u32"));
                out
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::InvalidEncoding);
        }
        let tag = bytes[0];
        let (body, rest) = dec_bytes(&bytes[1..])?;
        if !rest.is_empty() {
            return Err(Error::InvalidEncoding);
        }
        match tag {
            0 => Ok(DkgMessage::Commitment(DkgCommitment::decode(&body)?)),
            1 => Ok(DkgMessage::Share(DkgShare::decode(&body)?)),
            2 => Ok(DkgMessage::Complaint(DkgComplaint::decode(&body)?)),
            _ => Err(Error::InvalidEncoding),
        }
    }
}

impl Wire for DkgPublicParams {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&g2_to_bytes(&self.pk));
        out.extend_from_slice(&enc_len(self.pk_shares.len()).expect("length must fit u32"));
        for (id, pk_i) in self.pk_shares.iter() {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&g2_to_bytes(pk_i));
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 96 + 4 {
            return Err(Error::InvalidEncoding);
        }
        let pk = g2_from_bytes(&bytes[0..96])?;
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[96..100]);
        let n = u32::from_be_bytes(len_bytes) as usize;
        let mut offset = 100;
        let mut pk_shares = Vec::with_capacity(n);
        for _ in 0..n {
            if offset + 4 + 96 > bytes.len() {
                return Err(Error::InvalidEncoding);
            }
            let mut id_bytes = [0u8; 4];
            id_bytes.copy_from_slice(&bytes[offset..offset + 4]);
            let id = u32::from_be_bytes(id_bytes);
            offset += 4;
            let pk_i = g2_from_bytes(&bytes[offset..offset + 96])?;
            offset += 96;
            pk_shares.push((id, pk_i));
        }
        if offset != bytes.len() {
            return Err(Error::InvalidEncoding);
        }
        Ok(DkgPublicParams { pk, pk_shares })
    }
}

impl Wire for DkgPartySecret {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 32);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.share.to_bytes_be());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 4 + 32 {
            return Err(Error::InvalidEncoding);
        }
        let mut id_bytes = [0u8; 4];
        id_bytes.copy_from_slice(&bytes[0..4]);
        let id = u32::from_be_bytes(id_bytes);
        let share = Option::<Scalar>::from(Scalar::from_bytes_be(
            &bytes[4..36]
                .try_into()
                .map_err(|_| Error::InvalidEncoding)?,
        ))
        .ok_or(Error::InvalidEncoding)?;
        Ok(DkgPartySecret { id, share })
    }
}

pub fn compute_pk_from_shares(
    pk_shares: &[(PartyId, G2Projective)],
) -> Result<G2Projective, Error> {
    let ids: Vec<PartyId> = pk_shares.iter().map(|(id, _)| *id).collect();
    let vals: Vec<G2Projective> = pk_shares.iter().map(|(_, pk)| *pk).collect();
    combine_g2_at_zero(&ids, &vals)
}

fn hash_to_g2(msg: &[u8]) -> G2Projective {
    G2Projective::hash_to_curve(msg, b"MEMP-ENC-H2", &[])
}
