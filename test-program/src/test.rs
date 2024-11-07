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