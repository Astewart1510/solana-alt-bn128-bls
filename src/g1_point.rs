use core::ops::Add;
use std::process::Output;

use solana_bn254::{compression::prelude::{alt_bn128_g1_compress, alt_bn128_g1_decompress, G1}, prelude::{alt_bn128_addition, alt_bn128_multiplication}};

use crate::{BLSError,PrivKey};

#[derive(Clone)]
pub struct G1Point(pub [u8;64]);

#[derive(Clone)]
pub struct G1CompressedPoint(pub [u8;32]);

impl Add for G1Point {
    type Output = G1Point;

    fn add(self, rhs: Self) -> G1Point {
        let mut combined_input = [0u8; 128]; // Create a buffer large enough for both 64-byte arrays.

        unsafe {
            *(combined_input.as_mut_ptr() as *mut [u8;64]) = self.0;
            *(combined_input.as_mut_ptr().add(64) as *mut [u8;64]) = rhs.0;
        }

        // Call the addition function with the combined input.
        let result = alt_bn128_addition(&combined_input).unwrap();

        // Directly create a new G1Point from the result without intermediate allocations.
        G1Point(result.try_into().unwrap())
    }
}

impl TryFrom<PrivKey> for G1CompressedPoint {
    type Error = BLSError;

    fn try_from(value: PrivKey) -> Result<Self, Self::Error> {        
        let input = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            value.0[0], value.0[1], value.0[2], value.0[3], value.0[4], value.0[5], value.0[6], value.0[7],
            value.0[8], value.0[9], value.0[10], value.0[11], value.0[12], value.0[13], value.0[14], value.0[15],
            value.0[16], value.0[17], value.0[18], value.0[19], value.0[20], value.0[21], value.0[22], value.0[23],
            value.0[24], value.0[25], value.0[26], value.0[27], value.0[28], value.0[29], value.0[30], value.0[31],
        ];

        let mut g1_sol_uncompressed = [0;64];
        
        g1_sol_uncompressed.clone_from_slice(&alt_bn128_multiplication(&input).map_err(|_| BLSError::AltBN128MulError)?);
        let compressed = alt_bn128_g1_compress(&g1_sol_uncompressed).map_err(|_| BLSError::SecretKeyError)?;
        Ok(G1CompressedPoint(compressed))
    }
}

impl TryFrom<PrivKey> for G1Point {
    type Error = BLSError;

    fn try_from(value: PrivKey) -> Result<Self, Self::Error> {        
        let input = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            value.0[0], value.0[1], value.0[2], value.0[3], value.0[4], value.0[5], value.0[6], value.0[7],
            value.0[8], value.0[9], value.0[10], value.0[11], value.0[12], value.0[13], value.0[14], value.0[15],
            value.0[16], value.0[17], value.0[18], value.0[19], value.0[20], value.0[21], value.0[22], value.0[23],
            value.0[24], value.0[25], value.0[26], value.0[27], value.0[28], value.0[29], value.0[30], value.0[31],
        ];

        let mut g1_sol_uncompressed = [0;64];
        
        g1_sol_uncompressed.clone_from_slice(&alt_bn128_multiplication(&input).map_err(|_| BLSError::SecretKeyError)?);
        Ok(G1Point(g1_sol_uncompressed))
    }
}

impl TryFrom<G1Point> for G1CompressedPoint {
    type Error = BLSError;

    fn try_from(value: G1Point) -> Result<Self, Self::Error> {        
        Ok(G1CompressedPoint(alt_bn128_g1_compress(&value.0).map_err(|_| BLSError::G1PointCompressionError)?))
    }
}

impl TryFrom<G1CompressedPoint> for G1Point {
    type Error = BLSError;

    fn try_from(value: G1CompressedPoint) -> Result<Self, Self::Error> {        
        Ok(G1Point(alt_bn128_g1_decompress(&value.0).map_err(|_| BLSError::G1PointDecompressionError)?))
    }
}

#[cfg(test)]
mod tests {
    use crate::{g1_point::G1CompressedPoint, privkey::PrivKey, G2Point, Sha256Normalized};

    use super::G1Point;

    #[test]
    fn keygen_g1_compressed() {
        let privkey = PrivKey([0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4, 0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe, 0xba, 0xaf, 0xb5, 0xc9]);

        let pubkey = G1CompressedPoint::try_from(privkey).unwrap();

        assert_eq!("1dc638338aa8dff2fd75df809e9f335d1b979690e7e02f498f10bb7d2c4a50eb", hex::encode(pubkey.0));
    }

    #[test]
    fn keygen_g1_uncompressed() {
        let privkey = PrivKey([0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4, 0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe, 0xba, 0xaf, 0xb5, 0xc9]);

        let pubkey = G1Point::try_from(privkey).unwrap();

        assert_eq!(hex::encode(pubkey.0), "1dc638338aa8dff2fd75df809e9f335d1b979690e7e02f498f10bb7d2c4a50eb08251a23ad51acbc01e346941a724e4795c113481b5a81a6f526db3df4d2000b");
    }

    #[test]
    fn g1_aggregate() {
        let privkey_1 = PrivKey([0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4, 0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe, 0xba, 0xaf, 0xb5, 0xc9]);

        let privkey_2 = PrivKey([0x22, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4, 0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe, 0xba, 0xaf, 0xb5, 0xc9]);

        let sig_1 = privkey_1.sign::<Sha256Normalized, &str>("test").unwrap();

        let sig_2 = privkey_2.sign::<Sha256Normalized, &str>("test").unwrap();
        
        let pubkey_1 = G2Point::try_from(privkey_1).unwrap();

        let pubkey_2 = G2Point::try_from(privkey_2).unwrap();

        let sig_agg = sig_1 + sig_2;

        let pubkey_agg = pubkey_1 + pubkey_2;

        pubkey_agg.verify_signature::<Sha256Normalized, &str>(sig_agg.try_into().unwrap(), "test").unwrap(); 
    }
}