use solana_bls_alt_bn128::{G1CompressedPoint, G2CompressedPoint, G2Point, Sha256Normalized};

pub const pubkey: G2CompressedPoint = G2CompressedPoint([
    0x8b, 0x1a, 0xc6, 0x3e, 0x24, 0x4f, 0xa4, 0x19, 0x78, 0xf2, 0x84, 0xb4, 0x69, 0xa6, 0xcb,
    0xe4, 0xa8, 0xba, 0xeb, 0x71, 0x06, 0x30, 0xad, 0xcc, 0xf6, 0x9b, 0x27, 0xd4, 0xbd, 0x12,
    0xf5, 0x76, 0x1e, 0x88, 0xed, 0x4a, 0xeb, 0xd8, 0x43, 0x85, 0x3b, 0xf0, 0x24, 0x9c, 0x7c,
    0x2b, 0x37, 0xfb, 0xb0, 0xd1, 0x77, 0xdb, 0x37, 0xe6, 0xab, 0x29, 0xd8, 0x9d, 0x4e, 0x29,
    0x72, 0xdf, 0xff, 0x24,
]);

/// # Safety
///
/// Solana is very dangerous
#[no_mangle]
pub unsafe extern "C" fn entrypoint(_: *mut u8) -> u64 {
    let signature = G1CompressedPoint([
        0x82, 0x6e, 0x58, 0x71, 0x6e, 0xd0, 0x10, 0x01, 0x81, 0x14, 0x8b, 0x56, 0x47, 0xe8, 0xf0,
        0x79, 0x99, 0xa3, 0x63, 0x99, 0x11, 0x70, 0x95, 0x9e, 0x71, 0x82, 0x80, 0x14, 0x48, 0x5a,
        0xa4, 0x2c,
    ]);

    if pubkey.verify_signature::<Sha256Normalized, &str>(signature, "sample").is_ok() {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use mollusk_svm::Mollusk;
    use solana_sdk::{account::AccountSharedData, instruction::{AccountMeta, Instruction}};
    use solana_sdk::pubkey::Pubkey;
    use solana_sdk::pubkey;

    #[test]
    fn test() {
        let program_id = pubkey!("BL511111111111111111111111111111111111111111");

        let signer = Pubkey::new_unique();

        let instruction = Instruction::new_with_bytes(
            program_id,
            &[],
            vec![
                AccountMeta::new(signer, true),
            ],
        );

        let mollusk = Mollusk::new(&program_id, "target/deploy/solana_bls_alt_bn128_test");

        let _: mollusk_svm::result::InstructionResult = mollusk.process_instruction(
            &instruction,
            &[
                (signer, AccountSharedData::new(10000, 0, &Pubkey::default())),
            ],
        );
    }
}