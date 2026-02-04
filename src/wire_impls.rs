use std::io::Cursor;

use blstrs::{Compress, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use group::Curve;

use crate::encoding::{dec_bytes, enc_bytes};
use crate::types::{Error, Params, PartyInfo, Wire};

impl Wire for Vec<u8> {
    fn encode(&self) -> Vec<u8> {
        enc_bytes(self)
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (data, rest) = dec_bytes(bytes)?;
        if !rest.is_empty() {
            return Err(Error::InvalidEncoding);
        }
        Ok(data)
    }
}

impl Wire for Params {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&self.n.to_be_bytes());
        out.extend_from_slice(&self.t.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 8 {
            return Err(Error::InvalidEncoding);
        }
        let mut n_bytes = [0u8; 4];
        let mut t_bytes = [0u8; 4];
        n_bytes.copy_from_slice(&bytes[0..4]);
        t_bytes.copy_from_slice(&bytes[4..8]);
        Ok(Params {
            n: u32::from_be_bytes(n_bytes),
            t: u32::from_be_bytes(t_bytes),
        })
    }
}

impl Wire for PartyInfo {
    fn encode(&self) -> Vec<u8> {
        self.id.to_be_bytes().to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 4 {
            return Err(Error::InvalidEncoding);
        }
        let mut id_bytes = [0u8; 4];
        id_bytes.copy_from_slice(bytes);
        Ok(PartyInfo {
            id: u32::from_be_bytes(id_bytes),
        })
    }
}

impl Wire for Scalar {
    fn encode(&self) -> Vec<u8> {
        self.to_bytes_be().to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 32 {
            return Err(Error::InvalidEncoding);
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(bytes);
        Option::<Scalar>::from(Scalar::from_bytes_be(&raw)).ok_or(Error::InvalidEncoding)
    }
}

impl Wire for G1Projective {
    fn encode(&self) -> Vec<u8> {
        self.to_affine().to_compressed().as_ref().to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 48 {
            return Err(Error::InvalidEncoding);
        }
        let mut raw = [0u8; 48];
        raw.copy_from_slice(bytes);
        let affine = Option::<G1Affine>::from(G1Affine::from_compressed(&raw))
            .ok_or(Error::InvalidEncoding)?;
        Ok(affine.into())
    }
}

impl Wire for G2Projective {
    fn encode(&self) -> Vec<u8> {
        self.to_affine().to_compressed().as_ref().to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 96 {
            return Err(Error::InvalidEncoding);
        }
        let mut raw = [0u8; 96];
        raw.copy_from_slice(bytes);
        let affine = Option::<G2Affine>::from(G2Affine::from_compressed(&raw))
            .ok_or(Error::InvalidEncoding)?;
        Ok(affine.into())
    }
}

impl Wire for Gt {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(288);
        self.write_compressed(&mut bytes)
            .map_err(|_| Error::InvalidEncoding)
            .expect("in-memory serialization should not fail");
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut cursor = Cursor::new(bytes);
        Gt::read_compressed(&mut cursor).map_err(|_| Error::InvalidEncoding)
    }
}
