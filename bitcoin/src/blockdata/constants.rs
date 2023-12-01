// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Blockdata constants.
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction.
//!

use core::default::Default;

use bitcoin_internals::impl_array_newtype;
use hex_lit::hex;

use crate::hashes::{Hash, sha256d};
use crate::blockdata::script;
use crate::blockdata::opcodes::all::*;
use crate::blockdata::locktime::absolute;
use crate::blockdata::transaction::{OutPoint, Transaction, TxOut, TxIn, Sequence};
use crate::blockdata::block::{self, Block};
use crate::blockdata::witness::Witness;
use crate::network::constants::Network;
use crate::pow::CompactTarget;
use crate::internal_macros::impl_bytes_newtype;

// Qtum
pub use crate::hash_types::BlockHash;
use ckb_types::h256;

/// How many satoshis are in "one bitcoin".
pub const COIN_VALUE: u64 = 100_000_000;
/// How many seconds between blocks we expect on average.
pub const TARGET_BLOCK_SPACING: u32 = 600;
/// How many blocks between diffchanges.
pub const DIFFCHANGE_INTERVAL: u32 = 2016;
/// How much time on average should occur between diffchanges.
pub const DIFFCHANGE_TIMESPAN: u32 = 14 * 24 * 3600;
/// The maximum allowed weight for a block, see BIP 141 (network rule).
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
/// The minimum transaction weight for a valid serialized transaction.
pub const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;
/// The factor that non-witness serialization data is multiplied by during weight calculation.
pub const WITNESS_SCALE_FACTOR: usize = 4;
/// The maximum allowed number of signature check operations in a block.
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;
/// Mainnet (bitcoin) pubkey address prefix.
// pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 0; // 0x00
/// Mainnet (bitcoin) script address prefix.
// pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 5; // 0x05
/// Test (tesnet, signet, regtest) pubkey address prefix.
// pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 111; // 0x6f
/// Test (tesnet, signet, regtest) script address prefix.
// pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 196; // 0xc4

/// Mainnet (Qtum) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN_QTUM: u8 = 58; // 0x3a
/// Mainnet (Qtum) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN_QTUM: u8 = 50; // 0x32
/// Testnet (Qtum) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST_QTUM: u8 = 120; // 0x78
/// Testnet (Qtum) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST_QTUM: u8 = 110; // 0x6e


/// The maximum allowed script size.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// How may blocks between halvings.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 210_000;
/// Maximum allowed value for an integer in Script.
pub const MAX_SCRIPTNUM_VALUE: u32 = 0x80000000; // 2^31
/// Number of blocks needed for an output from a coinbase transaction to be spendable.
pub const COINBASE_MATURITY: u32 = 100;

/// The maximum value allowed in an output (useful for sanity checking,
/// since keeping everything below this value should prevent overflows
/// if you are doing anything remotely sane with monetary values).
pub const MAX_MONEY: u64 = 21_000_000 * COIN_VALUE;


// Qtum values can be found at https://github.com/qtumproject/qtum/blob/master/src/chainparams.cpp
// Qtum Genesis Block params: CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount &genesisReward)
// Qtum Mainnet: CreateGenesisBlock(1504695029, 8026361, 0x1f00ffff, 1, 50 * COIN);
const GENESIS_BLOCK_TIME_QTUM_MAIN: u32 = 1504695029;
const GENESIS_BLOCK_NONCE_QTUM_MAIN: u32 = 8026361;
const GENESIS_BLOCK_BITS_QTUM_MAIN: u32 = 0x1f00ffff;
// const GENESIS_BLOCK_VERSION_QTUM_MAIN: u32 = 1;
// const GENESIS_BLOCK_REWARD_QTUM_MAIN: u64 = 50 * COIN_VALUE;
// Qtum Testnet: CreateGenesisBlock(1504695029, 7349697, 0x1f00ffff, 1, 50 * COIN);
const GENESIS_BLOCK_TIME_QTUM_TEST: u32 = 1504695029;
const GENESIS_BLOCK_NONCE_QTUM_TEST: u32 = 7349697;
const GENESIS_BLOCK_BITS_QTUM_TEST: u32 = 0x1f00ffff;
// const GENESIS_BLOCK_VERSION_QTUM_TEST: u32 = 1;
// const GENESIS_BLOCK_REWARD_QTUM_TEST: u64 = 50 * COIN_VALUE;
// Qtum Signet: CreateGenesisBlock(1623662135, 7377285, 0x1f00ffff, 1, 50 * COIN);
const GENESIS_BLOCK_TIME_QTUM_SIGNET: u32 = 1623662135;
const GENESIS_BLOCK_NONCE_QTUM_SIGNET: u32 = 7377285;
const GENESIS_BLOCK_BITS_QTUM_SIGNET: u32 = 0x1f00ffff;
// const GENESIS_BLOCK_VERSION_QTUM_SIGNET: u32 = 1;
// const GENESIS_BLOCK_REWARD_QTUM_SIGNET: u64 = 50 * COIN_VALUE;
// Qtum Regtest: CreateGenesisBlock(1504695029, 17, 0x207fffff, 1, 50 * COIN);
const GENESIS_BLOCK_TIME_QTUM_REGTEST: u32 = 1504695029;
const GENESIS_BLOCK_NONCE_QTUM_REGTEST: u32 = 17;
const GENESIS_BLOCK_BITS_QTUM_REGTEST: u32 = 0x207fffff;

/// Constructs and returns the coinbase (and only) transaction of the Qtum genesis block.
fn bitcoin_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: 1,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    // Inputs
    let in_script = script::Builder::new().push_opcode(crate::opcodes::OP_0)
                                          .push_int(488804799)
                                          .push_int_non_minimal(4)
                                          .push_slice(b"Sep 02, 2017 Bitcoin breaks $5,000 in latest price frenzy")
                                          .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });

    // Outputs
    let script_bytes = hex!("040d61d8653448c98731ee5fffd303c15e71ec2057b77f11ab3601979728cdaff2d68afbba14e4fa0bc44f2072b0b23ef63717f8cdfbe58dcd33f32b6afe98741a");
    let out_script = script::Builder::new()
        .push_slice(script_bytes)
        .push_opcode(OP_CHECKSIG)
        .into_script();
    ret.output.push(TxOut {
        value: 50 * COIN_VALUE,
        script_pubkey: out_script
    });

    // end
    ret
}

/// Constructs and returns the genesis block.
pub fn genesis_block(network: Network) -> Block {
    let txdata = vec![bitcoin_genesis_tx()];
    let hash: sha256d::Hash = txdata[0].txid().into();
    let merkle_root = hash.into();

    // Qtum
    let hash_state_root: BlockHash = Hash::from_slice(h256!("0xe965ffd002cd6ad0e2dc402b8044de833e06b23127ea8c3d80aec91410771495").as_bytes()).unwrap();
    let hash_utxo_root: BlockHash = Hash::from_slice(keccak_hash::keccak(rlp::encode(&"").as_mut()).as_bytes()).unwrap();

    match network {
        Network::Qtum => {
            Block {
                header: block::Header {
                    version: block::Version::ONE,
                    prev_blockhash: Hash::all_zeros(),
                    merkle_root,
                    time: GENESIS_BLOCK_TIME_QTUM_MAIN,
                    bits: CompactTarget::from_consensus(GENESIS_BLOCK_BITS_QTUM_MAIN),
                    nonce: GENESIS_BLOCK_NONCE_QTUM_MAIN,
                    hash_state_root,
                    hash_utxo_root,
                    prevout_stake: OutPoint::null(),
                    signature: vec![],
                },
                txdata,
            }
        }
        Network::Testnet => {
            Block {
                header: block::Header {
                    version: block::Version::ONE,
                    prev_blockhash: Hash::all_zeros(),
                    merkle_root,
                    time: GENESIS_BLOCK_TIME_QTUM_TEST,
                    bits: CompactTarget::from_consensus(GENESIS_BLOCK_BITS_QTUM_TEST),
                    nonce: GENESIS_BLOCK_NONCE_QTUM_TEST,
                    hash_state_root,
                    hash_utxo_root,
                    prevout_stake: OutPoint::null(),
                    signature: vec![],
                },
                txdata,
            }
        }
        Network::Signet => {
            Block {
                header: block::Header {
                    version: block::Version::ONE,
                    prev_blockhash: Hash::all_zeros(),
                    merkle_root,
                    time: GENESIS_BLOCK_TIME_QTUM_SIGNET,
                    bits: CompactTarget::from_consensus(GENESIS_BLOCK_BITS_QTUM_SIGNET),
                    nonce: GENESIS_BLOCK_NONCE_QTUM_SIGNET,
                    hash_state_root,
                    hash_utxo_root,
                    prevout_stake: OutPoint::null(),
                    signature: vec![],
                },
                txdata,
            }
        }
        Network::Regtest => {
            Block {
                header: block::Header {
                    version: block::Version::ONE,
                    prev_blockhash: Hash::all_zeros(),
                    merkle_root,
                    time: GENESIS_BLOCK_TIME_QTUM_REGTEST,
                    bits: CompactTarget::from_consensus(GENESIS_BLOCK_BITS_QTUM_REGTEST),
                    nonce: GENESIS_BLOCK_NONCE_QTUM_REGTEST,
                    hash_state_root,
                    hash_utxo_root,
                    prevout_stake: OutPoint::null(),
                    signature: vec![],
                },
                txdata,
            }
        }
    }
}

/// The uniquely identifying hash of the target blockchain.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainHash([u8; 32]);
impl_array_newtype!(ChainHash, u8, 32);
impl_bytes_newtype!(ChainHash, 32);

impl ChainHash {
    /// Qtum values can be found at https://github.com/qtumproject/qtum/blob/master/src/chainparams.cpp
    // Qtum Mainnet Genesis Block Hash: "0x000075aef83cf2853580f8ae8ce6f8c3096cfa21d98334d6e3f95e5582ed986c"
    pub const QTUM: Self = Self([108, 152, 237, 130, 85, 94, 249, 227, 214, 52, 131, 217, 33,
        250, 108, 9, 195, 248, 230, 140, 174, 248, 128, 53, 133, 242, 60, 248, 174, 117, 0, 0
        ]);
    /// Qtum values can be found at https://github.com/qtumproject/qtum/blob/master/src/chainparams.cpp
    // Qtum Testnet Genesis Block Hash: "0x0000e803ee215c0684ca0d2f9220594d3f828617972aad66feb2ba51f5e14222"
    pub const TESTNET: Self = Self([34, 66, 225, 245, 81, 186, 178, 254, 102, 173, 42, 151, 23,
        134, 130, 63, 77, 89, 32, 146, 47, 13, 202, 132, 6, 92, 33, 238, 3, 232, 0, 0
        ]);
    /// Qtum values can be found at https://github.com/qtumproject/qtum/blob/master/src/chainparams.cpp
    // Qtum Signet Genesis Block Hash: "0x0000e0d4bc95abd1c0fcef0abb2795b6e8525f406262d59dc60cd3c490641347"
    pub const SIGNET: Self = Self([71, 19, 100, 144, 196, 211, 12, 198, 157, 213, 98, 98, 64, 95,
        82, 232, 182, 149, 39, 187, 10, 239, 252, 192, 209, 171, 149, 188, 212, 224, 0, 0
        ]);
    /// Qtum values can be found at https://github.com/qtumproject/qtum/blob/master/src/chainparams.cpp
    // Qtum Regtest Genesis Block Hash: "0x665ed5b402ac0b44efc37d8926332994363e8a7278b7ee9a58fb972efadae943"
    pub const REGTEST: Self = Self([67, 233, 218, 250, 46, 151, 251, 88, 154, 238, 183, 120, 114,
        138, 62, 54, 148, 41, 51, 38, 137, 125, 195, 239, 68, 11, 172, 2, 180, 213, 94, 102
        ]);

    /// Returns the hash of the `network` genesis block for use as a chain hash.
    ///
    /// See [BOLT 0](https://github.com/lightning/bolts/blob/ffeece3dab1c52efdb9b53ae476539320fa44938/00-introduction.md#chain_hash)
    /// for specification.
    pub const fn using_genesis_block(network: Network) -> Self {
        let hashes = [Self::QTUM, Self::TESTNET, Self::SIGNET, Self::REGTEST];
        hashes[network as usize]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::network::constants::Network;
    use crate::consensus::encode::serialize;
    use crate::blockdata::locktime::absolute;
    use crate::internal_macros::hex;

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let gen = bitcoin_genesis_tx();

        assert_eq!(gen.version, 1);
        assert_eq!(gen.input.len(), 1);
        assert_eq!(gen.input[0].previous_output.txid, Hash::all_zeros());
        assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        assert_eq!(serialize(&gen.input[0].script_sig),
                   hex!("420004bf91221d0104395365702030322c203230313720426974636f696e20627265616b732024352c30303020696e206c6174657374207072696365206672656e7a79"));

        assert_eq!(gen.input[0].sequence, Sequence::MAX);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey),
                   hex!("4341040d61d8653448c98731ee5fffd303c15e71ec2057b77f11ab3601979728cdaff2d68afbba14e4fa0bc44f2072b0b23ef63717f8cdfbe58dcd33f32b6afe98741aac"));
        assert_eq!(gen.output[0].value, 50 * COIN_VALUE);
        assert_eq!(gen.lock_time, absolute::LockTime::ZERO);

        assert_eq!(gen.wtxid().to_string(), "ed34050eb5909ee535fcb07af292ea55f3d2f291187617b44d3282231405b96d");
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(Network::Qtum);

        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(gen.header.merkle_root.to_string(), "ed34050eb5909ee535fcb07af292ea55f3d2f291187617b44d3282231405b96d");

        assert_eq!(gen.header.time, 1504695029);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1f00ffff));
        assert_eq!(gen.header.nonce, 8026361);
        assert_eq!(gen.header.block_hash().to_string(), "000075aef83cf2853580f8ae8ce6f8c3096cfa21d98334d6e3f95e5582ed986c");
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(Network::Testnet);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(gen.header.merkle_root.to_string(), "ed34050eb5909ee535fcb07af292ea55f3d2f291187617b44d3282231405b96d");
        assert_eq!(gen.header.time, 1504695029);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1f00ffff));
        assert_eq!(gen.header.nonce, 7349697);
        assert_eq!(gen.header.block_hash().to_string(), "0000e803ee215c0684ca0d2f9220594d3f828617972aad66feb2ba51f5e14222");
    }

    #[test]
    fn signet_genesis_full_block() {
        let gen = genesis_block(Network::Signet);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(gen.header.merkle_root.to_string(), "ed34050eb5909ee535fcb07af292ea55f3d2f291187617b44d3282231405b96d");
        assert_eq!(gen.header.time, 1623662135);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1f00ffff));
        assert_eq!(gen.header.nonce, 7377285);
        assert_eq!(gen.header.block_hash().to_string(), "0000e0d4bc95abd1c0fcef0abb2795b6e8525f406262d59dc60cd3c490641347");
    }

    // Qtum
    #[test]
    fn qtum_genesis_qtum_specific_fields() {
        let gen = genesis_block(Network::Qtum);

        assert_eq!(gen.header.hash_state_root.to_string(), "9514771014c9ae803d8cea2731b2063e83de44802b40dce2d06acd02d0ff65e9");
        assert_eq!(gen.header.hash_utxo_root.to_string(), "21b463e3b52f6201c0ad6c991be0485b6ef8c092e64583ffa655cc1b171fe856");
        assert_eq!(gen.header.prevout_stake, OutPoint::null());
        assert_eq!(gen.header.signature, Vec::<u8>::new());
    }

    // The *_chain_hash tests are sanity/regression tests, they verify that the const byte array
    // representing the genesis block is the same as that created by hashing the genesis block.
    fn chain_hash_and_genesis_block(network: Network) {
        use crate::hashes::sha256;

        // The genesis block hash is a double-sha256 and it is displayed backwards.
        let genesis_hash = genesis_block(network).block_hash();
        // We abuse the sha256 hash here so we get a LowerHex impl that does not print the hex backwards.
        let hash = sha256::Hash::from_slice(genesis_hash.as_byte_array()).unwrap();
        let want = format!("{:02x}", hash);

        let chain_hash = ChainHash::using_genesis_block(network);
        let got = format!("{:02x}", chain_hash);

        // Compare strings because the spec specifically states how the chain hash must encode to hex.
        assert_eq!(got, want);

        match network {
            Network::Qtum => {},
            Network::Testnet => {},
            Network::Signet => {},
            Network::Regtest => {},
            // Update ChainHash::using_genesis_block and chain_hash_genesis_block with new variants.
        }
    }

    macro_rules! chain_hash_genesis_block {
        ($($test_name:ident, $network:expr);* $(;)*) => {
            $(
                #[test]
                fn $test_name() {
                    chain_hash_and_genesis_block($network);
                }
            )*
        }
    }

    chain_hash_genesis_block! {
        mainnet_chain_hash_genesis_block, Network::Qtum;
        testnet_chain_hash_genesis_block, Network::Testnet;
        signet_chain_hash_genesis_block, Network::Signet;
        regtest_chain_hash_genesis_block, Network::Regtest;
    }

    // Test vector taken from: https://github.com/lightning/bolts/blob/master/00-introduction.md
    #[test]
    fn mainnet_chain_hash_test_vector() {
        let got = ChainHash::using_genesis_block(Network::Qtum).to_string();
        let want = "6c98ed82555ef9e3d63483d921fa6c09c3f8e68caef8803585f23cf8ae750000";
        assert_eq!(got, want);
    }
}
