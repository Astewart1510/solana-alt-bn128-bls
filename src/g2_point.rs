#[derive(Clone)]
pub struct G2Point(pub [u8; 128]);
#[derive(Clone)]
pub struct G2CompressedPoint(pub [u8; 64]);

use core::ops::Add;

#[cfg(not(target_os = "solana"))]
use ark_bn254::{Fr, G2Affine};
#[cfg(not(target_os = "solana"))]
use ark_ec::AffineRepr;
#[cfg(not(target_os = "solana"))]
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use solana_bn254::{
    compression::prelude::{alt_bn128_g2_compress, alt_bn128_g2_decompress},
    prelude::alt_bn128_pairing,
};

use crate::{BLSError, G1CompressedPoint, G1Point, HashToCurve, G2_MINUS_ONE};

#[cfg(not(target_os = "solana"))]
use crate::PrivKey;

impl G2Point {
    pub fn verify_signature<H: HashToCurve, T: AsRef<[u8]>>(
        self,
        signature: G1CompressedPoint,
        message: T,
    ) -> Result<(), BLSError> {
        let mut input = [0u8; 384];

        // 1) Hash message to curve
        input[..64].clone_from_slice(&H::try_hash_to_curve(message)?.0);
        // 2) Decompress our public key
        input[64..192].clone_from_slice(&self.0);
        // 3) Decompress our signature
        input[192..256].clone_from_slice(&G1Point::try_from(signature)?.0);
        // 4) Pair with -G2::one()
        input[256..].clone_from_slice(&G2_MINUS_ONE);

        // Calculate result
        if let Ok(r) = alt_bn128_pairing(&input) {
            if r.eq(&[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
            ]) {
                Ok(())
            } else {
                Err(BLSError::BLSVerificationError)
            }
        } else {
            Err(BLSError::AltBN128PairingError)
        }
    }
}

#[cfg(not(target_os = "solana"))]
impl Add for G2Point {
    type Output = G2Point;

    fn add(self, rhs: Self) -> G2Point {
        let mut s0 = G2CompressedPoint::try_from(self).unwrap().0;
        let mut s1 = G2CompressedPoint::try_from(rhs).unwrap().0;
        s0.reverse();
        s1.reverse();
        let g2_agg = G2Affine::deserialize_compressed(&s0[..]).unwrap()
            + G2Affine::deserialize_compressed(&s1[..]).unwrap();
        let mut g2_agg_bytes = [0u8; 64];
        g2_agg
            .serialize_compressed(&mut &mut g2_agg_bytes[..])
            .unwrap();

        g2_agg_bytes.reverse();

        G2Point::try_from(G2CompressedPoint(g2_agg_bytes)).unwrap()
    }
}

impl G2CompressedPoint {
    pub fn verify_signature<H: HashToCurve, T: AsRef<[u8]>>(
        self,
        signature: G1CompressedPoint,
        message: T,
    ) -> Result<(), BLSError> {
        let mut input = [0u8; 384];

        // 1) Hash message to curve
        input[..64].clone_from_slice(&H::try_hash_to_curve(message)?.0);
        // 2) Decompress our public key
        input[64..192].clone_from_slice(&G2Point::try_from(self)?.0);
        // 3) Decompress our signature
        input[192..256].clone_from_slice(&G1Point::try_from(signature)?.0);
        // 4) Pair with -G2::one()
        input[256..].clone_from_slice(&G2_MINUS_ONE);

        // Calculate result
        if let Ok(r) = alt_bn128_pairing(&input) {
            if r.eq(&[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
            ]) {
                Ok(())
            } else {
                Err(BLSError::BLSVerificationError)
            }
        } else {
            Err(BLSError::AltBN128PairingError)
        }
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<PrivKey> for G2CompressedPoint {
    type Error = BLSError;

    fn try_from(value: PrivKey) -> Result<G2CompressedPoint, Self::Error> {
        let mut pk = value.0;

        pk.reverse();

        let secret_key =
            Fr::deserialize_compressed(&pk[..]).map_err(|_| BLSError::SecretKeyError)?;

        let g2_public_key = G2Affine::generator() * secret_key;

        let mut g2_public_key_bytes = [0u8; 64];

        g2_public_key
            .serialize_compressed(&mut &mut g2_public_key_bytes[..])
            .map_err(|_| BLSError::G2PointCompressionError)?;

        g2_public_key_bytes.reverse();

        Ok(Self(g2_public_key_bytes))
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<PrivKey> for G2Point {
    type Error = BLSError;

    fn try_from(value: PrivKey) -> Result<G2Point, Self::Error> {
        Ok(G2Point(
            alt_bn128_g2_decompress(&G2CompressedPoint::try_from(value)?.0)
                .map_err(|_| BLSError::G2PointDecompressionError)?,
        ))
    }
}

impl TryFrom<G2Point> for G2CompressedPoint {
    type Error = BLSError;

    fn try_from(value: G2Point) -> Result<Self, Self::Error> {
        Ok(G2CompressedPoint(
            alt_bn128_g2_compress(&value.0).map_err(|_| BLSError::G2PointCompressionError)?,
        ))
    }
}

impl TryFrom<G2CompressedPoint> for G2Point {
    type Error = BLSError;

    fn try_from(value: G2CompressedPoint) -> Result<Self, Self::Error> {
        Ok(G2Point(
            alt_bn128_g2_decompress(&value.0).map_err(|_| BLSError::G2PointDecompressionError)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        g1_point::G1CompressedPoint,
        g2_point::{G2CompressedPoint, G2Point},
        privkey::PrivKey,
        schemes::sha256_normalized::Sha256Normalized,
    };

    #[test]
    fn keygen_g2_compressed() {
        let privkey = PrivKey([
            0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4,
            0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe,
            0xba, 0xaf, 0xb5, 0xc9,
        ]);
        let pubkey = G2CompressedPoint::try_from(privkey).unwrap();
        assert_eq!("8b1ac63e244fa41978f284b469a6cbe4a8baeb710630adccf69b27d4bd12f5761e88ed4aebd843853bf0249c7c2b37fbb0d177db37e6ab29d89d4e2972dfff24", hex::encode(pubkey.0));
    }

    #[test]
    fn keygen_g2_uncompressed() {
        let privkey = PrivKey([
            0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4,
            0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe,
            0xba, 0xaf, 0xb5, 0xc9,
        ]);

        let pubkey = G2Point::try_from(privkey).unwrap();

        assert_eq!("0b1ac63e244fa41978f284b469a6cbe4a8baeb710630adccf69b27d4bd12f5761e88ed4aebd843853bf0249c7c2b37fbb0d177db37e6ab29d89d4e2972dfff242d43aa4dd493e09a03b68c167f195b591ebcca6c2d438201fc4bfd9f9c0c3dda0ab848a49c6fdedc9de6083aff535ac65afd298af2a72767c19ad2aef5c4912c", hex::encode(&pubkey.0));
    }

    #[test]
    fn signature_verification() {
        let privkey = PrivKey([
            0x21, 0x6f, 0x05, 0xb4, 0x64, 0xd2, 0xca, 0xb2, 0x72, 0x95, 0x4c, 0x66, 0x0d, 0xd4,
            0x5c, 0xf8, 0xab, 0x0b, 0x26, 0x13, 0x65, 0x4d, 0xcc, 0xc7, 0x4c, 0x11, 0x55, 0xfe,
            0xba, 0xaf, 0xb5, 0xc9,
        ]);

        let signature = privkey.sign::<Sha256Normalized, &str>("sample").unwrap();

        let signature_compressed = G1CompressedPoint::try_from(signature).unwrap();

        let pubkey = G2CompressedPoint::try_from(privkey).unwrap();

        assert!(pubkey
            .verify_signature::<Sha256Normalized, &str>(signature_compressed, "sample")
            .is_ok());
    }
}
