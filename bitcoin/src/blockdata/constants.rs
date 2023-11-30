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

/// Constructs and returns the coinbase (and only) transaction of the Bitcoin genesis block.
fn bitcoin_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: 1,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    // Inputs
    let in_script = script::Builder::new().push_int(486604799)
                                          .push_int_non_minimal(4)
                                          .push_slice(b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks")
                                          .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: Sequence::MAX,
        witness: Witness::default(),
    });

    // Outputs
    let script_bytes = hex!("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f");
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
                    // ! TODO: UPDATE THESE VALUES WITH REAL QTUM VALUES
                    hash_state_root: Hash::all_zeros(),
                    hash_utxo_root: Hash::all_zeros(),
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
                    // ! TODO: UPDATE THESE VALUES WITH REAL QTUM VALUES
                    hash_state_root: Hash::all_zeros(),
                    hash_utxo_root: Hash::all_zeros(),
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
                    // ! TODO: UPDATE THESE VALUES WITH REAL QTUM VALUES
                    hash_state_root: Hash::all_zeros(),
                    hash_utxo_root: Hash::all_zeros(),
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
                    // ! TODO: UPDATE THESE VALUES WITH REAL QTUM VALUES
                    hash_state_root: Hash::all_zeros(),
                    hash_utxo_root: Hash::all_zeros(),
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
    pub const QTUM: Self = Self([0, 0, 117, 174, 248, 60, 242, 133, 53, 128, 248, 174, 140, 230, 
        248, 195, 9, 108, 250, 33, 217, 131, 52, 214, 227, 249, 94, 85, 130, 237, 152, 108
        ]);
    /// Qtum values can be found at https://github.com/qtumproject/qtum/blob/master/src/chainparams.cpp
     // Qtum Testnet Genesis Block Hash: "0x0000e803ee215c0684ca0d2f9220594d3f828617972aad66feb2ba51f5e14222"
    pub const TESTNET: Self = Self([0, 0, 232, 3, 238, 33, 92, 6, 132, 202, 13, 47, 146, 32, 89,
        77, 63, 130, 134, 23, 151, 42, 173, 102, 254, 178, 186, 81, 245, 225, 66, 34
        ]);
    /// Qtum values can be found at https://github.com/qtumproject/qtum/blob/master/src/chainparams.cpp
     // Qtum Signet Genesis Block Hash: "0xed34050eb5909ee535fcb07af292ea55f3d2f291187617b44d3282231405b96d"
    pub const SIGNET: Self = Self([237, 52, 5, 14, 181, 144, 158, 229, 53, 252, 176, 122, 242, 146, 
        234, 85, 243, 210, 242, 145, 24, 118, 23, 180, 77, 50, 130, 35, 20, 5, 185, 109
        ]);
    /// Qtum values can be found at https://github.com/qtumproject/qtum/blob/master/src/chainparams.cpp
    // Qtum Regtest Genesis Block Hash: "0x665ed5b402ac0b44efc37d8926332994363e8a7278b7ee9a58fb972efadae943"
    pub const REGTEST: Self = Self([102, 94, 213, 180, 2, 172, 11, 68, 239, 195, 125, 137, 38, 51, 
        41, 148, 54, 62, 138, 114, 120, 183, 238, 154, 88, 251, 151, 46, 250, 218, 233, 67
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
                   hex!("4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73"));

        assert_eq!(gen.input[0].sequence, Sequence::MAX);
        assert_eq!(gen.output.len(), 1);
        assert_eq!(serialize(&gen.output[0].script_pubkey),
                   hex!("434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"));
        assert_eq!(gen.output[0].value, 50 * COIN_VALUE);
        assert_eq!(gen.lock_time, absolute::LockTime::ZERO);

        assert_eq!(gen.wtxid().to_string(), "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(Network::Qtum);

        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(gen.header.merkle_root.to_string(), "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");

        assert_eq!(gen.header.time, 1231006505);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1d00ffff));
        assert_eq!(gen.header.nonce, 2083236893);
        assert_eq!(gen.header.block_hash().to_string(), "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(Network::Testnet);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(gen.header.merkle_root.to_string(), "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
        assert_eq!(gen.header.time, 1296688602);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1d00ffff));
        assert_eq!(gen.header.nonce, 414098458);
        assert_eq!(gen.header.block_hash().to_string(), "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943");
    }

    #[test]
    fn signet_genesis_full_block() {
        let gen = genesis_block(Network::Signet);
        assert_eq!(gen.header.version, block::Version::ONE);
        assert_eq!(gen.header.prev_blockhash, Hash::all_zeros());
        assert_eq!(gen.header.merkle_root.to_string(), "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
        assert_eq!(gen.header.time, 1598918400);
        assert_eq!(gen.header.bits, CompactTarget::from_consensus(0x1e0377ae));
        assert_eq!(gen.header.nonce, 52613770);
        assert_eq!(gen.header.block_hash().to_string(), "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6");
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
        let want = "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000";
        assert_eq!(got, want);
    }
}
