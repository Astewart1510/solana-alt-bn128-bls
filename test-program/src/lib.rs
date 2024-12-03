use solana_alt_bn128_bls::{G1CompressedPoint, G2CompressedPoint, Sha256Normalized};
use pinocchio::{account_info::AccountInfo, entrypoint, program_error::ProgramError, pubkey::Pubkey, ProgramResult};

pub const PUBKEY: G2CompressedPoint = G2CompressedPoint([
    0x26, 0xe7, 0x58, 0x78, 0x4a, 0x55, 0x3f, 0xe9, 0xe9, 0x09, 0x2c, 0xdd, 0x05, 0xea, 0xa3, 0xb9,
    0x2c, 0xb5, 0xd9, 0x30, 0xa1, 0xd4, 0x8b, 0xde, 0xb9, 0xbe, 0x8f, 0x0f, 0x6f, 0x09, 0xc9, 0xda,
    0x08, 0x20, 0xd2, 0x42, 0xbc, 0x90, 0x71, 0xa8, 0x49, 0x8b, 0x46, 0x87, 0xa2, 0x51, 0x9f, 0xb0,
    0x22, 0xb2, 0xec, 0xb4, 0xcb, 0x99, 0x34, 0xdb, 0x57, 0xc1, 0xc0, 0x03, 0xda, 0x3c, 0x1f, 0x83,
]);

#[no_mangle]
pub static IDL: &str = "https://github.com/org/repo/idl.json";

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],  // Serialized instruction-specific data
) -> ProgramResult {
    let (signature_bytes, message) = instruction_data.split_at(32);

    let signature = G1CompressedPoint(signature_bytes.try_into().unwrap());

    PUBKEY
        .verify_signature::<Sha256Normalized, &[u8], G1CompressedPoint>(signature, &message).map_err(|_| ProgramError::MissingRequiredSignature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use mollusk_svm::Mollusk;
    use solana_sdk::pubkey;
    use solana_sdk::pubkey::Pubkey;
    use solana_sdk::{
        account::AccountSharedData,
        instruction::{AccountMeta, Instruction},
    };

    #[test]
    fn test() {
        let program_id = pubkey!("B1sA1tBn128111111111111111111111111111111111");

        let signer = Pubkey::new_unique();

        let instruction_data: Vec<u8> = [
            &[
                0x2b, 0x04, 0x16, 0xb5, 0xd0, 0x58, 0xe8, 0xb3, 0x13, 0x42, 0x4d, 0x3e, 0x71, 0xec, 0x61,
                0xa3, 0x62, 0x42, 0xdb, 0xa0, 0x31, 0xc3, 0x53, 0xd9, 0xa0, 0x21, 0xbe, 0x4f, 0x5a, 0xed,
                0x22, 0x7a,
            ],
            &50_000u64.to_le_bytes()[..], 
            b"BTCUSD<"
        ].concat();


        let instruction =
            Instruction::new_with_bytes(program_id, &instruction_data, vec![AccountMeta::new(signer, true)]);

        let mollusk = Mollusk::new(&program_id, "target/deploy/solana_bls_alt_bn128_test");

        let _: mollusk_svm::result::InstructionResult = mollusk.process_instruction(
            &instruction,
            &[(signer, AccountSharedData::new(10000, 0, &Pubkey::default()))],
        );
    }
}
