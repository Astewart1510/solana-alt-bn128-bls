use solana_bn254::prelude::alt_bn128_multiplication;

use crate::{errors::BLSError, g1_point::G1Point, schemes::HashToCurve};

pub struct PrivKey(pub [u8;32]);

impl PrivKey {
    pub fn sign<H: HashToCurve, T: AsRef<[u8]>>(&self, message: T) -> Result<G1Point, BLSError> {
        let point = H::try_hash_to_curve::<T>(message)?;

        let input = vec![
            &point.0[..],
            &self.0[..]
        ].concat();

        let mut g1_sol_uncompressed = [0x00u8; 64];
        g1_sol_uncompressed.clone_from_slice(&alt_bn128_multiplication(&input).map_err(|_| BLSError::BLSSigningError)?);
        
        Ok(G1Point(g1_sol_uncompressed))
    }
}

#[cfg(test)]
mod test {
    use crate::{g1_point::G1CompressedPoint, schemes::sha256_normalized::Sha256Normalized};

    use super::PrivKey;

    #[test]
    fn sign() {
        let privkey = PrivKey([0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4, 0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe, 0xba, 0xaf, 0xb5, 0xc9]);
        let signature = privkey.sign::<Sha256Normalized, &[u8;6]>(b"sample").unwrap();
        assert_eq!(hex::encode(signature.0), "026e58716ed0100181148b5647e8f07999a363991170959e71828014485aa42c2ecd1df173228c3f2a5c9fd20d4418ca6c108b50e076630916cc570ec15a772a");
    }

    #[test]
    fn sign_compressed() {
        let privkey = PrivKey([0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4, 0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe, 0xba, 0xaf, 0xb5, 0xc9]);
        let signature = G1CompressedPoint::try_from(privkey.sign::<Sha256Normalized, &[u8;6]>(b"sample").unwrap()).unwrap();
        assert_eq!(hex::encode(signature.0), "826e58716ed0100181148b5647e8f07999a363991170959e71828014485aa42c");
    }
}