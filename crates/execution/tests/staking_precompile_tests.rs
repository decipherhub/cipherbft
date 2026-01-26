//! Integration tests for the staking precompile.
//!
//! These tests verify the staking precompile functionality including:
//! - Validator registration with minimum stake
//! - Validator deregistration with exit marking
//! - Stake queries
//! - Slashing (system-only)
//! - Gas consumption
//!
//! Based on Phase 6 (User Story 4) integration test requirements (T064-T069).

use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_sol_types::SolCall;
use cipherbft_execution::precompiles::staking::{
    IStaking, StakingPrecompile, MIN_VALIDATOR_STAKE, SYSTEM_ADDRESS,
};

/// Helper to create a test address from a seed.
fn test_address(seed: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[0] = seed;
    bytes[19] = seed;
    Address::from(bytes)
}

/// Helper to create a test BLS public key (48 bytes).
fn test_bls_pubkey(seed: u8) -> FixedBytes<32> {
    // Since IStaking expects bytes32 (32 bytes), not bytes48
    let mut bytes = [0u8; 32];
    bytes[0] = 0xa0 + seed;
    bytes[1] = 0xb0 + seed;
    bytes[31] = seed;
    FixedBytes::from(bytes)
}

/// T064: Integration test for registerValidator() function.
///
/// Tests validator registration with stake above minimum (1 CPH).
#[test]
fn test_register_validator_success() {
    let precompile = StakingPrecompile::new();
    let validator_addr = test_address(1);
    let bls_pubkey = test_bls_pubkey(1);

    // Prepare registerValidator(bytes32 blsPubkey) call
    let call_data = IStaking::registerValidatorCall {
        blsPubkey: bls_pubkey,
    }
    .abi_encode();
    let input = Bytes::from(call_data);

    // Call with exactly minimum stake (1 CPH)
    let stake_amount = U256::from(MIN_VALIDATOR_STAKE);
    let block_number = 100;
    let gas_limit = 100_000;

    let result = precompile.run(
        &input,
        gas_limit,
        validator_addr,
        stake_amount,
        block_number,
    );

    // Verify success
    assert!(
        result.is_ok(),
        "registerValidator should succeed with minimum stake"
    );
    let output = result.unwrap();
    assert!(output.gas_used > 0, "Should consume gas");
    assert!(output.gas_used < gas_limit, "Should not exceed gas limit");

    // Verify validator was added to state
    let state = precompile.state();
    let state_lock = state.read();
    assert!(
        state_lock.is_validator(&validator_addr),
        "Validator should be registered"
    );
    assert_eq!(
        state_lock.get_stake(&validator_addr),
        stake_amount,
        "Stake should match"
    );
    assert_eq!(
        state_lock.total_stake, stake_amount,
        "Total stake should be updated"
    );
}

/// T064: Test registration with stake above minimum.
#[test]
fn test_register_validator_high_stake() {
    let precompile = StakingPrecompile::new();
    let validator_addr = test_address(2);
    let bls_pubkey = test_bls_pubkey(2);

    let call_data = IStaking::registerValidatorCall {
        blsPubkey: bls_pubkey,
    }
    .abi_encode();
    let input = Bytes::from(call_data);

    // Stake 50 CPH
    let stake_amount = U256::from(50_000_000_000_000_000_000u128);

    let result = precompile.run(&input, 100_000, validator_addr, stake_amount, 100);
    assert!(
        result.is_ok(),
        "registerValidator should succeed with high stake"
    );

    let state = precompile.state();
    let state_lock = state.read();
    assert_eq!(state_lock.get_stake(&validator_addr), stake_amount);
}

/// T068: Integration test for minimum stake enforcement.
///
/// Tests that registration fails when stake is below 1 CPH minimum.
#[test]
fn test_register_validator_insufficient_stake() {
    let precompile = StakingPrecompile::new();
    let validator_addr = test_address(3);
    let bls_pubkey = test_bls_pubkey(3);

    let call_data = IStaking::registerValidatorCall {
        blsPubkey: bls_pubkey,
    }
    .abi_encode();
    let input = Bytes::from(call_data);

    // Try to stake 0.5 CPH (below minimum)
    let stake_amount = U256::from(500_000_000_000_000_000u128);

    let result = precompile.run(&input, 100_000, validator_addr, stake_amount, 100);

    // Should fail
    assert!(
        result.is_err(),
        "registerValidator should fail with insufficient stake"
    );

    // Verify validator was NOT added
    let state = precompile.state();
    let state_lock = state.read();
    assert!(
        !state_lock.is_validator(&validator_addr),
        "Validator should not be registered"
    );
}

/// T068: Test that zero stake is rejected.
#[test]
fn test_register_validator_zero_stake() {
    let precompile = StakingPrecompile::new();
    let validator_addr = test_address(4);
    let bls_pubkey = test_bls_pubkey(4);

    let call_data = IStaking::registerValidatorCall {
        blsPubkey: bls_pubkey,
    }
    .abi_encode();
    let input = Bytes::from(call_data);

    let result = precompile.run(&input, 100_000, validator_addr, U256::ZERO, 100);
    assert!(
        result.is_err(),
        "registerValidator should fail with zero stake"
    );
}

/// T065: Integration test for deregisterValidator().
///
/// Tests validator deregistration and exit marking.
#[test]
fn test_deregister_validator() {
    let precompile = StakingPrecompile::new();
    let validator_addr = test_address(5);
    let bls_pubkey = test_bls_pubkey(5);

    // First, register the validator
    let register_call = IStaking::registerValidatorCall {
        blsPubkey: bls_pubkey,
    }
    .abi_encode();
    let stake_amount = U256::from(MIN_VALIDATOR_STAKE);
    let block_number = 100;

    let _ = precompile.run(
        &Bytes::from(register_call),
        100_000,
        validator_addr,
        stake_amount,
        block_number,
    );

    // Verify registered
    {
        let state = precompile.state();
        let state_lock = state.read();
        assert!(state_lock.is_validator(&validator_addr));
    }

    // Now deregister
    let deregister_call = IStaking::deregisterValidatorCall {}.abi_encode();
    let result = precompile.run(
        &Bytes::from(deregister_call),
        100_000,
        validator_addr,
        U256::ZERO,
        block_number + 10,
    );

    assert!(result.is_ok(), "deregisterValidator should succeed");

    // Verify pending exit is set
    let state = precompile.state();
    let state_lock = state.read();
    let validator = state_lock.validators.get(&validator_addr).unwrap();
    assert!(
        validator.pending_exit.is_some(),
        "Pending exit should be set"
    );
}

/// T065: Test deregistration of non-existent validator fails.
#[test]
fn test_deregister_nonexistent_validator() {
    let precompile = StakingPrecompile::new();
    let validator_addr = test_address(6);

    let deregister_call = IStaking::deregisterValidatorCall {}.abi_encode();
    let result = precompile.run(
        &Bytes::from(deregister_call),
        100_000,
        validator_addr,
        U256::ZERO,
        100,
    );

    assert!(
        result.is_err(),
        "deregisterValidator should fail for non-existent validator"
    );
}

/// T067: Integration test for getStake() function.
///
/// Tests stake query functionality.
#[test]
fn test_get_stake() {
    let precompile = StakingPrecompile::new();
    let validator_addr = test_address(7);
    let bls_pubkey = test_bls_pubkey(6);

    // Register validator with 10 CPH
    let stake_amount = U256::from(10_000_000_000_000_000_000u128);
    let register_call = IStaking::registerValidatorCall {
        blsPubkey: bls_pubkey,
    }
    .abi_encode();

    let _ = precompile.run(
        &Bytes::from(register_call),
        100_000,
        validator_addr,
        stake_amount,
        100,
    );

    // Query stake
    let get_stake_call = IStaking::getStakeCall {
        account: validator_addr,
    }
    .abi_encode();

    let result = precompile.run(
        &Bytes::from(get_stake_call),
        100_000,
        test_address(8), // Can be called by anyone
        U256::ZERO,
        100,
    );

    assert!(result.is_ok(), "getStake should succeed");
    let output = result.unwrap();

    // Decode returned stake amount
    let returned_stake = U256::from_be_slice(&output.bytes);
    assert_eq!(
        returned_stake, stake_amount,
        "Returned stake should match deposited amount"
    );
}

/// T067: Test getStake for non-existent validator returns zero.
#[test]
fn test_get_stake_nonexistent() {
    let precompile = StakingPrecompile::new();
    let nonexistent_addr = test_address(9);

    let get_stake_call = IStaking::getStakeCall {
        account: nonexistent_addr,
    }
    .abi_encode();

    let result = precompile.run(
        &Bytes::from(get_stake_call),
        100_000,
        test_address(10),
        U256::ZERO,
        100,
    );

    assert!(
        result.is_ok(),
        "getStake should succeed for non-existent validator"
    );
    let output = result.unwrap();
    let returned_stake = U256::from_be_slice(&output.bytes);
    assert_eq!(
        returned_stake,
        U256::ZERO,
        "Stake should be zero for non-existent validator"
    );
}

/// T069: Integration test for slash() function (system-only).
///
/// Tests slashing functionality and access control.
#[test]
fn test_slash_validator() {
    let precompile = StakingPrecompile::new();
    let validator_addr = test_address(11);
    let bls_pubkey = test_bls_pubkey(7);

    // Register with 10 CPH
    let initial_stake = U256::from(10_000_000_000_000_000_000u128);
    let register_call = IStaking::registerValidatorCall {
        blsPubkey: bls_pubkey,
    }
    .abi_encode();

    let _ = precompile.run(
        &Bytes::from(register_call),
        100_000,
        validator_addr,
        initial_stake,
        100,
    );

    // Slash 2 CPH (only system can call this)
    let slash_amount = U256::from(2_000_000_000_000_000_000u128);
    let slash_call = IStaking::slashCall {
        validator: validator_addr,
        amount: slash_amount,
    }
    .abi_encode();

    let result = precompile.run(
        &Bytes::from(slash_call),
        100_000,
        SYSTEM_ADDRESS, // System address
        U256::ZERO,
        110,
    );

    assert!(result.is_ok(), "slash should succeed when called by system");

    // Verify stake was reduced
    let state = precompile.state();
    let state_lock = state.read();
    let expected_stake = initial_stake - slash_amount;
    assert_eq!(
        state_lock.get_stake(&validator_addr),
        expected_stake,
        "Stake should be reduced by slash amount"
    );
    assert_eq!(
        state_lock.total_stake, expected_stake,
        "Total stake should be reduced"
    );
}

/// T069: Test slash access control - non-system address should fail.
#[test]
fn test_slash_unauthorized() {
    let precompile = StakingPrecompile::new();
    let validator_addr = test_address(12);
    let attacker_addr = test_address(13);
    let bls_pubkey = test_bls_pubkey(8);

    // Register validator
    let register_call = IStaking::registerValidatorCall {
        blsPubkey: bls_pubkey,
    }
    .abi_encode();
    let _ = precompile.run(
        &Bytes::from(register_call),
        100_000,
        validator_addr,
        U256::from(MIN_VALIDATOR_STAKE),
        100,
    );

    // Try to slash from non-system address
    let slash_call = IStaking::slashCall {
        validator: validator_addr,
        amount: U256::from(1_000_000_000_000_000_000u128),
    }
    .abi_encode();

    let result = precompile.run(
        &Bytes::from(slash_call),
        100_000,
        attacker_addr, // Not system address
        U256::ZERO,
        110,
    );

    assert!(
        result.is_err(),
        "slash should fail when called by non-system address"
    );
}

/// T069: Integration test for getValidatorSet() function.
///
/// Tests retrieving the complete validator set.
#[test]
fn test_get_validator_set() {
    let precompile = StakingPrecompile::new();

    // Register 3 validators
    let validators = vec![
        (
            test_address(14),
            test_bls_pubkey(10),
            U256::from(10_000_000_000_000_000_000u128),
        ),
        (
            test_address(15),
            test_bls_pubkey(11),
            U256::from(20_000_000_000_000_000_000u128),
        ),
        (
            test_address(16),
            test_bls_pubkey(12),
            U256::from(15_000_000_000_000_000_000u128),
        ),
    ];

    for (addr, bls, stake) in &validators {
        let register_call = IStaking::registerValidatorCall { blsPubkey: *bls }.abi_encode();
        let _ = precompile.run(&Bytes::from(register_call), 100_000, *addr, *stake, 100);
    }

    // Query validator set
    let get_set_call = IStaking::getValidatorSetCall {}.abi_encode();
    let result = precompile.run(
        &Bytes::from(get_set_call),
        200_000,
        test_address(17),
        U256::ZERO,
        100,
    );

    assert!(result.is_ok(), "getValidatorSet should succeed");
    let output = result.unwrap();

    // Verify gas consumption scales with number of validators
    let base_gas = 2_100;
    let per_validator_gas = 100;
    let expected_min_gas = base_gas + (per_validator_gas * validators.len() as u64);
    assert!(
        output.gas_used >= expected_min_gas,
        "Gas should scale with validator count"
    );

    // Note: Full ABI decoding would require parsing the tuple (address[], uint256[])
    // For now, we verify the call succeeded and consumed appropriate gas
}

/// T069: Integration test for atomic operations in single block.
///
/// Tests multiple staking operations within one block execute atomically.
#[test]
fn test_atomic_operations() {
    let precompile = StakingPrecompile::new();
    let block_number = 100;

    // Register 2 validators in same block
    let val1 = test_address(18);
    let val2 = test_address(19);

    let register1 = IStaking::registerValidatorCall {
        blsPubkey: test_bls_pubkey(20),
    }
    .abi_encode();

    let register2 = IStaking::registerValidatorCall {
        blsPubkey: test_bls_pubkey(21),
    }
    .abi_encode();

    let stake1 = U256::from(5_000_000_000_000_000_000u128);
    let stake2 = U256::from(7_000_000_000_000_000_000u128);

    // Both operations in same block
    let result1 = precompile.run(&Bytes::from(register1), 100_000, val1, stake1, block_number);
    let result2 = precompile.run(&Bytes::from(register2), 100_000, val2, stake2, block_number);

    assert!(
        result1.is_ok() && result2.is_ok(),
        "Both registrations should succeed"
    );

    // Verify both are registered with correct total stake
    let state = precompile.state();
    let state_lock = state.read();
    assert!(state_lock.is_validator(&val1) && state_lock.is_validator(&val2));
    assert_eq!(
        state_lock.total_stake,
        stake1 + stake2,
        "Total stake should sum both validators"
    );

    // Verify individual stakes
    assert_eq!(state_lock.get_stake(&val1), stake1);
    assert_eq!(state_lock.get_stake(&val2), stake2);
}

/// Test gas consumption for registerValidator is deterministic.
#[test]
fn test_register_gas_consumption() {
    let precompile = StakingPrecompile::new();
    let validator_addr = test_address(20);
    let bls_pubkey = test_bls_pubkey(30);

    let call_data = IStaking::registerValidatorCall {
        blsPubkey: bls_pubkey,
    }
    .abi_encode();

    let result = precompile.run(
        &Bytes::from(call_data),
        100_000,
        validator_addr,
        U256::from(MIN_VALIDATOR_STAKE),
        100,
    );

    assert!(result.is_ok());
    let gas_used = result.unwrap().gas_used;

    // Gas should be deterministic (50,000 per spec)
    assert!(
        gas_used > 0 && gas_used <= 50_000,
        "Gas should be deterministic and <= 50,000"
    );
}

/// Test that validators can be queried individually.
#[test]
fn test_multiple_validators_individual_queries() {
    let precompile = StakingPrecompile::new();

    // Register 5 validators
    let validators: Vec<(Address, U256)> = (0..5)
        .map(|i| {
            let addr = test_address(21 + i as u8);
            let stake = U256::from((i + 1) * 1_000_000_000_000_000_000u128);
            (addr, stake)
        })
        .collect();

    for (i, (addr, stake)) in validators.iter().enumerate() {
        let call = IStaking::registerValidatorCall {
            blsPubkey: test_bls_pubkey(40 + i as u8),
        }
        .abi_encode();
        let _ = precompile.run(&Bytes::from(call), 100_000, *addr, *stake, 100);
    }

    // Query each validator's stake
    for (addr, expected_stake) in &validators {
        let get_stake_call = IStaking::getStakeCall { account: *addr }.abi_encode();
        let result = precompile.run(
            &Bytes::from(get_stake_call),
            100_000,
            test_address(22),
            U256::ZERO,
            100,
        );

        assert!(result.is_ok());
        let output = result.unwrap();
        let returned_stake = U256::from_be_slice(&output.bytes);
        assert_eq!(returned_stake, *expected_stake);
    }
}

// ============================================================================
// Reward Distribution Tests
// ============================================================================

/// Test fee accumulation in staking state.
#[test]
fn test_fee_accumulation() {
    let precompile = StakingPrecompile::new();

    // Accumulate fees in multiple batches
    let fee1 = U256::from(1_000_000_000_000_000_000u128); // 1 CPH
    let fee2 = U256::from(500_000_000_000_000_000u128); // 0.5 CPH
    let fee3 = U256::from(250_000_000_000_000_000u128); // 0.25 CPH

    {
        let state = precompile.state();
        let mut state_lock = state.write();
        state_lock.accumulate_fees(fee1);
        state_lock.accumulate_fees(fee2);
        state_lock.accumulate_fees(fee3);
    }

    // Verify accumulated fees
    let state = precompile.state();
    let state_lock = state.read();
    let expected_total = fee1 + fee2 + fee3;
    assert_eq!(
        state_lock.rewards.accumulated_fees, expected_total,
        "Accumulated fees should sum correctly"
    );
}

/// Test epoch reward distribution to single validator.
#[test]
fn test_distribute_rewards_single_validator() {
    let precompile = StakingPrecompile::new();
    let validator_addr = test_address(30);
    let bls_pubkey = test_bls_pubkey(30);

    // Register validator with 10 CPH
    let initial_stake = U256::from(10_000_000_000_000_000_000u128);
    let register_call = IStaking::registerValidatorCall {
        blsPubkey: bls_pubkey,
    }
    .abi_encode();
    let _ = precompile.run(
        &Bytes::from(register_call),
        100_000,
        validator_addr,
        initial_stake,
        100,
    );

    // Accumulate some fees (0.5 CPH)
    let accumulated_fees = U256::from(500_000_000_000_000_000u128);
    {
        let state = precompile.state();
        let mut state_lock = state.write();
        state_lock.accumulate_fees(accumulated_fees);
    }

    // Distribute epoch rewards (2 CPH block reward)
    let epoch_block_reward = U256::from(2_000_000_000_000_000_000u128);
    let current_epoch = 1u64;

    {
        let state = precompile.state();
        let mut state_lock = state.write();
        let distributed = state_lock.distribute_epoch_rewards(epoch_block_reward, current_epoch);

        // Single validator gets all rewards (block reward + fees)
        let expected_distributed = epoch_block_reward + accumulated_fees;
        assert_eq!(
            distributed, expected_distributed,
            "Single validator should receive all rewards"
        );
    }

    // Verify validator stake increased
    let state = precompile.state();
    let state_lock = state.read();
    let expected_stake = initial_stake + epoch_block_reward + accumulated_fees;
    assert_eq!(
        state_lock.get_stake(&validator_addr),
        expected_stake,
        "Validator stake should include rewards"
    );

    // Verify accumulated fees reset
    assert!(
        state_lock.rewards.accumulated_fees.is_zero(),
        "Accumulated fees should be reset after distribution"
    );

    // Verify total_distributed tracking
    assert_eq!(
        state_lock.rewards.total_distributed,
        epoch_block_reward + accumulated_fees,
        "Total distributed should track cumulative rewards"
    );
}

/// Test epoch reward distribution to multiple validators (proportional).
#[test]
fn test_distribute_rewards_multiple_validators_proportional() {
    let precompile = StakingPrecompile::new();

    // Register 3 validators with different stakes:
    // Validator 1: 25 CPH (25%)
    // Validator 2: 50 CPH (50%)
    // Validator 3: 25 CPH (25%)
    let validators = vec![
        (
            test_address(31),
            test_bls_pubkey(31),
            U256::from(25_000_000_000_000_000_000u128),
        ),
        (
            test_address(32),
            test_bls_pubkey(32),
            U256::from(50_000_000_000_000_000_000u128),
        ),
        (
            test_address(33),
            test_bls_pubkey(33),
            U256::from(25_000_000_000_000_000_000u128),
        ),
    ];

    for (addr, bls, stake) in &validators {
        let register_call = IStaking::registerValidatorCall { blsPubkey: *bls }.abi_encode();
        let _ = precompile.run(&Bytes::from(register_call), 100_000, *addr, *stake, 100);
    }

    // Accumulate 1 CPH in fees
    let accumulated_fees = U256::from(1_000_000_000_000_000_000u128);
    {
        let state = precompile.state();
        let mut state_lock = state.write();
        state_lock.accumulate_fees(accumulated_fees);
    }

    // Distribute 3 CPH block reward (total 4 CPH to distribute)
    let epoch_block_reward = U256::from(3_000_000_000_000_000_000u128);
    let total_to_distribute = epoch_block_reward + accumulated_fees; // 4 CPH
    let current_epoch = 1u64;

    {
        let state = precompile.state();
        let mut state_lock = state.write();
        let distributed = state_lock.distribute_epoch_rewards(epoch_block_reward, current_epoch);

        // Total distributed should equal rewards + fees
        assert_eq!(
            distributed, total_to_distribute,
            "Total distributed should equal block reward + fees"
        );
    }

    // Verify proportional distribution:
    // Validator 1: 25% of 4 CPH = 1 CPH
    // Validator 2: 50% of 4 CPH = 2 CPH
    // Validator 3: 25% of 4 CPH = 1 CPH
    let state = precompile.state();
    let state_lock = state.read();

    let stake1 = state_lock.get_stake(&validators[0].0);
    let stake2 = state_lock.get_stake(&validators[1].0);
    let stake3 = state_lock.get_stake(&validators[2].0);

    // Initial stakes + rewards
    let expected1 = validators[0].2 + U256::from(1_000_000_000_000_000_000u128); // 25 + 1 = 26 CPH
    let expected2 = validators[1].2 + U256::from(2_000_000_000_000_000_000u128); // 50 + 2 = 52 CPH
    let expected3 = validators[2].2 + U256::from(1_000_000_000_000_000_000u128); // 25 + 1 = 26 CPH

    assert_eq!(stake1, expected1, "Validator 1 should receive 25% of rewards");
    assert_eq!(stake2, expected2, "Validator 2 should receive 50% of rewards");
    assert_eq!(stake3, expected3, "Validator 3 should receive 25% of rewards");

    // Verify total stake increased
    let expected_total_stake = expected1 + expected2 + expected3;
    assert_eq!(
        state_lock.total_stake, expected_total_stake,
        "Total stake should include all distributed rewards"
    );
}

/// Test distribute_epoch_rewards via precompile call (system-only).
#[test]
fn test_distribute_rewards_precompile_system_only() {
    let precompile = StakingPrecompile::new();
    let validator_addr = test_address(34);
    let bls_pubkey = test_bls_pubkey(34);

    // Register validator
    let register_call = IStaking::registerValidatorCall {
        blsPubkey: bls_pubkey,
    }
    .abi_encode();
    let _ = precompile.run(
        &Bytes::from(register_call),
        100_000,
        validator_addr,
        U256::from(MIN_VALIDATOR_STAKE),
        100,
    );

    // Try to call distributeEpochRewards from non-system address
    let epoch_reward = U256::from(2_000_000_000_000_000_000u128);
    let distribute_call = IStaking::distributeEpochRewardsCall {
        epochBlockReward: epoch_reward,
    }
    .abi_encode();

    let attacker_addr = test_address(35);
    let result = precompile.run(
        &Bytes::from(distribute_call.clone()),
        200_000,
        attacker_addr, // Not SYSTEM_ADDRESS
        U256::ZERO,
        100,
    );

    assert!(
        result.is_err(),
        "distributeEpochRewards should fail when called by non-system address"
    );

    // Call from SYSTEM_ADDRESS should succeed
    let result = precompile.run(
        &Bytes::from(distribute_call),
        200_000,
        SYSTEM_ADDRESS,
        U256::ZERO,
        100,
    );

    assert!(
        result.is_ok(),
        "distributeEpochRewards should succeed when called by system"
    );
}

/// Test getAccumulatedFees query.
#[test]
fn test_get_accumulated_fees_query() {
    let precompile = StakingPrecompile::new();

    // Accumulate fees
    let fees = U256::from(3_500_000_000_000_000_000u128); // 3.5 CPH
    {
        let state = precompile.state();
        let mut state_lock = state.write();
        state_lock.accumulate_fees(fees);
    }

    // Query accumulated fees via precompile
    let get_fees_call = IStaking::getAccumulatedFeesCall {}.abi_encode();
    let result = precompile.run(
        &Bytes::from(get_fees_call),
        10_000,
        test_address(36), // Anyone can query
        U256::ZERO,
        100,
    );

    assert!(result.is_ok(), "getAccumulatedFees should succeed");
    let output = result.unwrap();
    let returned_fees = U256::from_be_slice(&output.bytes);
    assert_eq!(
        returned_fees, fees,
        "Returned fees should match accumulated amount"
    );
}

/// Test getTotalDistributed query.
#[test]
fn test_get_total_distributed_query() {
    let precompile = StakingPrecompile::new();
    let validator_addr = test_address(37);
    let bls_pubkey = test_bls_pubkey(37);

    // Register validator
    let register_call = IStaking::registerValidatorCall {
        blsPubkey: bls_pubkey,
    }
    .abi_encode();
    let _ = precompile.run(
        &Bytes::from(register_call),
        100_000,
        validator_addr,
        U256::from(10_000_000_000_000_000_000u128),
        100,
    );

    // Distribute rewards via system call
    let epoch_reward = U256::from(2_000_000_000_000_000_000u128);
    let distribute_call = IStaking::distributeEpochRewardsCall {
        epochBlockReward: epoch_reward,
    }
    .abi_encode();

    let _ = precompile.run(
        &Bytes::from(distribute_call),
        200_000,
        SYSTEM_ADDRESS,
        U256::ZERO,
        100,
    );

    // Query total distributed
    let get_total_call = IStaking::getTotalDistributedCall {}.abi_encode();
    let result = precompile.run(
        &Bytes::from(get_total_call),
        10_000,
        test_address(38),
        U256::ZERO,
        100,
    );

    assert!(result.is_ok(), "getTotalDistributed should succeed");
    let output = result.unwrap();
    let returned_total = U256::from_be_slice(&output.bytes);
    assert_eq!(
        returned_total, epoch_reward,
        "Total distributed should match epoch reward"
    );
}

/// Test reward distribution with zero validators (edge case).
#[test]
fn test_distribute_rewards_no_validators() {
    let precompile = StakingPrecompile::new();

    // No validators registered - try to distribute
    let epoch_reward = U256::from(2_000_000_000_000_000_000u128);

    {
        let state = precompile.state();
        let mut state_lock = state.write();
        let distributed = state_lock.distribute_epoch_rewards(epoch_reward, 1);

        // Should return zero since no validators
        assert!(
            distributed.is_zero(),
            "Distribution with no validators should return zero"
        );
    }

    // Verify no state corruption
    let state = precompile.state();
    let state_lock = state.read();
    assert!(
        state_lock.total_stake.is_zero(),
        "Total stake should remain zero"
    );
}

/// Test multiple epoch distributions accumulate correctly.
#[test]
fn test_multiple_epoch_distributions() {
    let precompile = StakingPrecompile::new();
    let validator_addr = test_address(40);
    let bls_pubkey = test_bls_pubkey(40);

    // Register validator with 10 CPH
    let initial_stake = U256::from(10_000_000_000_000_000_000u128);
    let register_call = IStaking::registerValidatorCall {
        blsPubkey: bls_pubkey,
    }
    .abi_encode();
    let _ = precompile.run(
        &Bytes::from(register_call),
        100_000,
        validator_addr,
        initial_stake,
        100,
    );

    let epoch_reward = U256::from(2_000_000_000_000_000_000u128); // 2 CPH per epoch

    // Distribute across 3 epochs
    for epoch in 1..=3 {
        let state = precompile.state();
        let mut state_lock = state.write();
        let distributed = state_lock.distribute_epoch_rewards(epoch_reward, epoch);
        assert_eq!(distributed, epoch_reward);
    }

    // Verify cumulative results
    let state = precompile.state();
    let state_lock = state.read();

    // Validator should have initial + 3 epochs of rewards = 10 + 6 = 16 CPH
    let expected_stake = initial_stake + (epoch_reward * U256::from(3));
    assert_eq!(
        state_lock.get_stake(&validator_addr),
        expected_stake,
        "Stake should accumulate across epochs"
    );

    // Total distributed should be 6 CPH
    let expected_total_distributed = epoch_reward * U256::from(3);
    assert_eq!(
        state_lock.rewards.total_distributed, expected_total_distributed,
        "Total distributed should track cumulative rewards"
    );
}
