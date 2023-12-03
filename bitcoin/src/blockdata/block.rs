// Written in 2014 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blocks.
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.
//!

use crate::prelude::*;

use core::fmt;

use crate::merkle_tree;
use crate::error::Error::{self, BlockBadTarget, BlockBadProofOfWork};
use crate::hashes::{Hash, HashEngine};
use crate::hash_types::{Wtxid, TxMerkleNode, WitnessMerkleNode, WitnessCommitment};
use crate::consensus::{encode, Encodable, Decodable};
use crate::blockdata::transaction::{OutPoint, Transaction};
use crate::blockdata::script;
use crate::pow::{CompactTarget, Target, Work};
use crate::VarInt;
use crate::internal_macros::impl_consensus_encoding;
use crate::io;
use super::Weight;
// #[cfg(feature = "serde")]
// use serde::{Serialize, Deserialize};

pub use crate::hash_types::BlockHash;

/// Blockflag is used to indicate the type of block in Qtum
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlockFlag {
    /// Proof of work Qtum block
    ProofOfWork,
    /// Proof of stake Qtum block
    ProofOfStake,
}

// ! Implement Encodable and Decodable for BlockFlag
impl Encodable for BlockFlag {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        match self {
            BlockFlag::ProofOfWork => 0u8.consensus_encode(w),
            BlockFlag::ProofOfStake => 1u8.consensus_encode(w),
        }
    }
}

impl Decodable for BlockFlag {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let flag = u8::consensus_decode(r)?;
        match flag {
            0 => Ok(BlockFlag::ProofOfWork),
            1 => Ok(BlockFlag::ProofOfStake),
            _ => Err(encode::Error::ParseFailed("Invalid block flag")),
        }
    }
}
// ! Implement Serialize and Deserialize for BlockFlag
#[cfg(feature = "serde")]
impl serde::Serialize for BlockFlag {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            BlockFlag::ProofOfWork => s.serialize_u8(0),
            BlockFlag::ProofOfStake => s.serialize_u8(1),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for BlockFlag {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let flag = u8::deserialize(d)?;
        match flag {
            0 => Ok(BlockFlag::ProofOfWork),
            1 => Ok(BlockFlag::ProofOfStake),
            _ => Err(serde::de::Error::custom("Invalid block flag")),
        }
    }
}

/// Bitcoin block header.
///
/// Contains all the block's information except the actual transactions, but
/// including a root of a [merkle tree] commiting to all transactions in the block.
///
/// [merkle tree]: https://en.wikipedia.org/wiki/Merkle_tree
///
/// ### Bitcoin Core References
///
/// * [CBlockHeader definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L20)
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Header {
    /// Block version, now repurposed for soft fork signalling.
    pub version: Version,
    /// Reference to the previous block in the chain.
    pub prev_blockhash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block.
    pub merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner.
    pub time: u32,
    /// The target value below which the blockhash must lie.
    pub bits: CompactTarget,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,
    // start of qtum specific fields
    /// Qtum: hashStateRoot
    pub hash_state_root: BlockHash,
    /// Qtum: hashUTXORoot
    pub hash_utxo_root: BlockHash,
    /// Qtum: prevoutStake
    pub prevout_stake: OutPoint,
    /// Qtum: vchBlockSigDlgt
    pub signature: Vec<u8>,
    // end of qtum specific block fields
}

impl_consensus_encoding!(Header, version, prev_blockhash, merkle_root, time, bits, nonce, hash_state_root, hash_utxo_root, prevout_stake, signature);

impl Header {
    /// Returns the block hash.
    pub fn block_hash(&self) -> BlockHash {
        let mut engine = BlockHash::engine();
        self.consensus_encode(&mut engine).expect("engines don't error");
        BlockHash::from_engine(engine)
    }

    /// Computes the target (range [0, T] inclusive) that a blockhash must land in to be valid.
    pub fn target(&self) -> Target {
        self.bits.into()
    }

    /// Computes the popular "difficulty" measure for mining.
    pub fn difficulty(&self) -> u128 {
        self.target().difficulty()
    }

    /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
    pub fn difficulty_float(&self) -> f64 {
        self.target().difficulty_float()
    }

    /// Qtum: checks if the blook is proof-of-stake.
    pub fn is_pos(&self) -> bool {
        !self.prevout_stake.is_null()
    }

    /// Checks that the proof-of-work for the block is valid, returning the block hash.
    pub fn validate_pow(&self, required_target: Target) -> Result<BlockHash, Error> {
        let target = self.target();
        if target != required_target {
            return Err(BlockBadTarget);
        }
        let block_hash = self.block_hash();
        if target.is_met_by(block_hash) {
            Ok(block_hash)
        } else {
            Err(BlockBadProofOfWork)
        }
    }

    /// Returns the total work of the block.
    pub fn work(&self) -> Work {
        self.target().to_work()
    }
}

/// Bitcoin block version number.
///
/// Originally used as a protocol version, but repurposed for soft-fork signaling.
///
/// The inner value is a signed integer in Bitcoin Core for historical reasons, if version bits is
/// being used the top three bits must be 001, this gives us a useful range of [0x20000000...0x3FFFFFFF].
///
/// > When a block nVersion does not have top bits 001, it is treated as if all bits are 0 for the purposes of deployments.
///
/// ### Relevant BIPs
///
/// * [BIP9 - Version bits with timeout and delay](https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki) (current usage)
/// * [BIP34 - Block v2, Height in Coinbase](https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki)
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Version(i32);

impl Version {
    /// The original Bitcoin Block v1.
    pub const ONE: Self = Self(1);

    /// BIP-34 Block v2.
    pub const TWO: Self = Self(2);

    /// BIP-9 compatible version number that does not signal for any softforks.
    pub const NO_SOFT_FORK_SIGNALLING: Self = Self(Self::USE_VERSION_BITS as i32);

    /// BIP-9 soft fork signal bits mask.
    const VERSION_BITS_MASK: u32 = 0x1FFF_FFFF;

    /// 32bit value starting with `001` to use version bits.
    ///
    /// The value has the top three bits `001` which enables the use of version bits to signal for soft forks.
    const USE_VERSION_BITS: u32 = 0x2000_0000;

    /// Creates a [`Version`] from a signed 32 bit integer value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    pub fn from_consensus(v: i32) -> Self {
        Version(v)
    }

    /// Returns the inner `i32` value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    pub fn to_consensus(self) -> i32 {
        self.0
    }

    /// Checks whether the version number is signalling a soft fork at the given bit.
    ///
    /// A block is signalling for a soft fork under BIP-9 if the first 3 bits are `001` and
    /// the version bit for the specific soft fork is toggled on.
    pub fn is_signalling_soft_fork(&self, bit: u8) -> bool {
        // Only bits [0, 28] inclusive are used for signalling.
        if bit > 28 {
            return false;
        }

        // To signal using version bits, the first three bits must be `001`.
        if (self.0 as u32) & !Self::VERSION_BITS_MASK != Self::USE_VERSION_BITS {
            return false;
        }

        // The bit is set if signalling a soft fork.
        (self.0 as u32 & Self::VERSION_BITS_MASK) & (1 << bit) > 0
    }
}

impl Default for Version {
    fn default() -> Version {
        Self::NO_SOFT_FORK_SIGNALLING
    }
}

impl Encodable for Version {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for Version {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Decodable::consensus_decode(r).map(Version)
    }
}

/// Bitcoin block.
///
/// A collection of transactions with an attached proof of work.
///
/// See [Bitcoin Wiki: Block][wiki-block] for more information.
///
/// [wiki-block]: https://en.bitcoin.it/wiki/Block
///
/// ### Bitcoin Core References
///
/// * [CBlock definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L62)
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Block {
    /// The block header
    pub header: Header,
    /// List of transactions contained in the block
    pub txdata: Vec<Transaction>
}

impl_consensus_encoding!(Block, header, txdata);

impl Block {
    /// Returns the block hash.
    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    /// Checks if merkle root of header matches merkle root of the transaction list.
    pub fn check_merkle_root(&self) -> bool {
        match self.compute_merkle_root() {
            Some(merkle_root) => self.header.merkle_root == merkle_root,
            None => false,
        }
    }

    /// Checks if witness commitment in coinbase matches the transaction list.
    pub fn check_witness_commitment(&self) -> bool {
        const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        // Witness commitment is optional if there are no transactions using SegWit in the block.
        if self.txdata.iter().all(|t| t.input.iter().all(|i| i.witness.is_empty())) {
            return true;
        }

        if self.txdata.is_empty() {
            return false;
        }

        let coinbase = &self.txdata[0];
        if !coinbase.is_coin_base() {
            return false;
        }

        // Commitment is in the last output that starts with magic bytes.
        if let Some(pos) = coinbase.output.iter()
            .rposition(|o| o.script_pubkey.len () >= 38 && o.script_pubkey.as_bytes()[0..6] ==  MAGIC)
        {
            let commitment = WitnessCommitment::from_slice(&coinbase.output[pos].script_pubkey.as_bytes()[6..38]).unwrap();
            // Witness reserved value is in coinbase input witness.
            let witness_vec: Vec<_> = coinbase.input[0].witness.iter().collect();
            if witness_vec.len() == 1 && witness_vec[0].len() == 32 {
                if let Some(witness_root) = self.witness_root() {
                    return commitment == Self::compute_witness_commitment(&witness_root, witness_vec[0]);
                }
            }
        }

        false
    }

    /// Computes the transaction merkle root.
    pub fn compute_merkle_root(&self) -> Option<TxMerkleNode> {
        let hashes = self.txdata.iter().map(|obj| obj.txid().to_raw_hash());
        merkle_tree::calculate_root(hashes).map(|h| h.into())
    }

    /// Computes the witness commitment for the block's transaction list.
    pub fn compute_witness_commitment(witness_root: &WitnessMerkleNode, witness_reserved_value: &[u8]) -> WitnessCommitment {
        let mut encoder = WitnessCommitment::engine();
        witness_root.consensus_encode(&mut encoder).expect("engines don't error");
        encoder.input(witness_reserved_value);
        WitnessCommitment::from_engine(encoder)
    }

    /// Computes the merkle root of transactions hashed for witness.
    pub fn witness_root(&self) -> Option<WitnessMerkleNode> {
        let hashes = self.txdata.iter().enumerate().map(|(i, t)| {
            if i == 0 {
                // Replace the first hash with zeroes.
                Wtxid::all_zeros().to_raw_hash()
            } else {
                t.wtxid().to_raw_hash()
            }
        });
        merkle_tree::calculate_root(hashes).map(|h| h.into())
    }

    /// base_size == size of header + size of encoded transaction count.
    fn base_size(&self) -> usize {
        // Qtum: header size is 181 byte
        181 + VarInt(self.txdata.len() as u64).len()
    }

    /// Returns the size of the block.
    ///
    /// size == size of header + size of encoded transaction count + total size of transactions.
    pub fn size(&self) -> usize {
        let txs_size: usize = self.txdata.iter().map(Transaction::size).sum();
        self.base_size() + txs_size
    }

    /// Returns the strippedsize of the block.
    pub fn strippedsize(&self) -> usize {
        let txs_size: usize = self.txdata.iter().map(Transaction::strippedsize).sum();
        self.base_size() + txs_size
    }

    /// Returns the weight of the block.
    pub fn weight(&self) -> Weight {
        let base_weight = Weight::from_non_witness_data_size(self.base_size() as u64);
        let txs_weight: Weight = self.txdata.iter().map(Transaction::weight).sum();
        base_weight + txs_weight
    }

    /// Returns the coinbase transaction, if one is present.
    pub fn coinbase(&self) -> Option<&Transaction> {
        self.txdata.first()
    }

    /// Returns the block height, as encoded in the coinbase transaction according to BIP34.
    pub fn bip34_block_height(&self) -> Result<u64, Bip34Error> {
        // Citing the spec:
        // Add height as the first item in the coinbase transaction's scriptSig,
        // and increase block version to 2. The format of the height is
        // "minimally encoded serialized CScript"" -- first byte is number of bytes in the number
        // (will be 0x03 on main net for the next 150 or so years with 2^23-1
        // blocks), following bytes are little-endian representation of the
        // number (including a sign bit). Height is the height of the mined
        // block in the block chain, where the genesis block is height zero (0).

        if self.header.version < Version::TWO {
            return Err(Bip34Error::Unsupported);
        }

        let cb = self.coinbase().ok_or(Bip34Error::NotPresent)?;
        let input = cb.input.first().ok_or(Bip34Error::NotPresent)?;
        let push = input.script_sig.instructions_minimal().next().ok_or(Bip34Error::NotPresent)?;
        match push.map_err(|_| Bip34Error::NotPresent)? {
            script::Instruction::PushBytes(b) => {
                // Check that the number is encoded in the minimal way.
                let h = script::read_scriptint(b.as_bytes()).map_err(|_e| Bip34Error::UnexpectedPush(b.as_bytes().to_vec()))?;
                if h < 0 {
                    Err(Bip34Error::NegativeHeight)
                } else {
                    Ok(h as u64)
                }
            }
            _ => Err(Bip34Error::NotPresent),
        }
    }
}

/// An error when looking up a BIP34 block height.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bip34Error {
    /// The block does not support BIP34 yet.
    Unsupported,
    /// No push was present where the BIP34 push was expected.
    NotPresent,
    /// The BIP34 push was larger than 8 bytes.
    UnexpectedPush(Vec<u8>),
    /// The BIP34 push was negative.
    NegativeHeight,
}

impl fmt::Display for Bip34Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Bip34Error::Unsupported => write!(f, "block doesn't support BIP34"),
            Bip34Error::NotPresent => write!(f, "BIP34 push not present in block's coinbase"),
            Bip34Error::UnexpectedPush(ref p) => {
                write!(f, "unexpected byte push of > 8 bytes: {:?}", p)
            }
            Bip34Error::NegativeHeight => write!(f, "negative BIP34 height"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Bip34Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Bip34Error::*;

        match self {
            Unsupported |
            NotPresent |
            UnexpectedPush(_) |
            NegativeHeight => None,
        }
    }
}

impl From<Header> for BlockHash {
    fn from(header: Header) -> BlockHash {
        header.block_hash()
    }
}

impl From<&Header> for BlockHash {
    fn from(header: &Header) -> BlockHash {
        header.block_hash()
    }
}

impl From<Block> for BlockHash {
    fn from(block: Block) -> BlockHash {
        block.block_hash()
    }
}

impl From<&Block> for BlockHash {
    fn from(block: &Block) -> BlockHash {
        block.block_hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // QTUM TODO!
    // use crate::hashes::hex::FromHex;
    use crate::consensus::encode::{deserialize, serialize};
    use crate::internal_macros::hex;

    #[test]
    fn test_coinbase_and_bip34() {
        // testnet block 1000
        const BLOCK_HEX: &str = "000000201b2aeed9c15769abdce798148c0b425456479d884833512d298fdb5d827c00008952d46e1ad68112e9e1f726affa4d955f28dd90aa759f5a0098ea6934245b908116cf59ffff001fa9eb0000e965ffd002cd6ad0e2dc402b8044de833e06b23127ea8c3d80aec9141077149556e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4210000000000000000000000000000000000000000000000000000000000000000ffffffff000102000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0502e8030102ffffffff0200204aa9d1010000232102c781355bd115fd37d04c6967e98c665b1bb32829f681989caa2758eebb4e0578ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX)).unwrap();

        let cb_txid = "905b243469ea98005a9f75aa90dd285f954dfaaf26f7e1e91281d61a6ed45289";
        assert_eq!(block.coinbase().unwrap().txid().to_string(), cb_txid);

        assert_eq!(block.bip34_block_height(), Ok(1_000));

        /*
        // QTUM TODO!
        // block with 9-byte bip34 push
        const BAD_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3d09a08601112233445566000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let bad: Block = deserialize(&hex!(BAD_HEX)).unwrap();

        let push = Vec::<u8>::from_hex("a08601112233445566").unwrap();
        assert_eq!(bad.bip34_block_height(), Err(super::Bip34Error::UnexpectedPush(push)));
        */
    }

    #[test]
    fn block_test() {
        // Mainnet block 0000fd3c4ed0b6dcb008b2669a3321de220d5b0716cc2984893d25111cbf5e51
        let some_block = hex!("0300002097d2cb7dbeb2c1a01e60870a3e48ce8e832bdc0d00cfa8603dae648862b50000f201aacca12a387a7c0bc18f7bc1b33dea5d828fcead35807cc7b3672a1fbc545f37b259ffff001f6d430000e965ffd002cd6ad0e2dc402b8044de833e06b23127ea8c3d80aec9141077149556e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4210000000000000000000000000000000000000000000000000000000000000000ffffffff000102000000010000000000000000000000000000000000000000000000000000000000000000ffffffff050283130101ffffffff0200204aa9d1010000232103043044049b375a128ed9c97f1d4e4857b648488da1c85ead04817be0173b06fcac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000000");
        let cutoff_block = hex!("0300002097d2cb7dbeb2c1a01e60870a3e48ce8e832bdc0d00cfa8603dae648862b50000f201aacca12a387a7c0bc18f7bc1b33dea5d828fcead35807cc7b3672a1fbc545f37b259ffff001f6d430000e965ffd002cd6ad0e2dc402b8044de833e06b23127ea8c3d80aec9141077149556e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4210000000000000000000000000000000000000000000000000000000000000000ffffffff000102000000010000000000000000000000000000000000000000000000000000000000000000ffffffff050283130101ffffffff0200204aa9d1010000232103043044049b375a128ed9c97f1d4e4857b648488da1c85ead04817be0173b06fcac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9");

        let prevhash = hex!("97d2cb7dbeb2c1a01e60870a3e48ce8e832bdc0d00cfa8603dae648862b50000");
        let merkle = hex!("f201aacca12a387a7c0bc18f7bc1b33dea5d828fcead35807cc7b3672a1fbc54");
        let work = Work::from(0x000010001_u128);

        let decode: Result<Block, _> = deserialize(&some_block);
        let bad_decode: Result<Block, _> = deserialize(&cutoff_block);

        assert!(decode.is_ok());
        assert!(bad_decode.is_err());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(536870915));
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.time, 1504851807);
        assert_eq!(real_decode.header.bits, CompactTarget::from_consensus(520159231));
        assert_eq!(real_decode.header.nonce, 17261);
        assert_eq!(real_decode.header.work(), work);
        if !real_decode.header.is_pos() {
            assert_eq!(real_decode.header.validate_pow(real_decode.header.target()).unwrap(), real_decode.block_hash());
        }
        assert_eq!(real_decode.header.difficulty(), 0);
        assert_eq!(real_decode.header.difficulty_float(), 1.52587890625e-05);
        // [test] TODO: check the transaction data

        assert_eq!(real_decode.size(), some_block.len());
        assert_eq!(real_decode.strippedsize(), some_block.len());
        assert_eq!(real_decode.weight(), Weight::from_non_witness_data_size(some_block.len() as u64));

        // should be also ok for a non-witness block as commitment is optional in that case
        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), some_block);
    }

    // Check testnet block 1d4dbf11b2f51d129e8d8f8ac33474432dd1fc10d8bcc77567830a0f123e397e
    #[test]
    fn segwit_block_test() {
        let segwit_block = include_bytes!("../../tests/data/testnet_block_1d4dbf11b2f51d129e8d8f8ac33474432dd1fc10d8bcc77567830a0f123e397e.raw").to_vec();

        let decode: Result<Block, _> = deserialize(&segwit_block);

        let prevhash = hex!("225af41883428d8625ee48c1a9ad2c097ea308d8f3b508f0df334a42723687db");
        let merkle = hex!("5c74f53ef806efc12b5debfe7c5becc26c899bcd476efeca50e389a63cd7283a");
        let work = Work::from(0x14d5a5a59209be_u64);

        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(Version::USE_VERSION_BITS as i32));  // VERSIONBITS but no bits set
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(real_decode.header.time, 1576204816);
        assert_eq!(real_decode.header.bits, CompactTarget::from_consensus(0x1a0c498b));
        assert_eq!(real_decode.header.nonce, 0);
        assert_eq!(real_decode.header.work(), work);
        if !real_decode.header.is_pos() {
            assert_eq!(real_decode.header.validate_pow(real_decode.header.target()).unwrap(), real_decode.block_hash());
        }
        assert_eq!(real_decode.header.difficulty(), 1365392);
        assert_eq!(real_decode.header.difficulty_float(), 1365392.812200795);
        // [test] TODO: check the transaction data

        /*
        // QTUM TODO!
        assert_eq!(real_decode.size(), segwit_block.len());
        assert_eq!(real_decode.strippedsize(), 7461);
        assert_eq!(real_decode.weight(), Weight::from_wu(29880));

        //assert!(real_decode.check_witness_commitment());
        */

        assert_eq!(serialize(&real_decode), segwit_block);
    }

    #[test]
    fn block_version_test() {
        let block = hex!("ffffff7f1b2aeed9c15769abdce798148c0b425456479d884833512d298fdb5d827c00008952d46e1ad68112e9e1f726affa4d955f28dd90aa759f5a0098ea6934245b908116cf59ffff001fa9eb0000e965ffd002cd6ad0e2dc402b8044de833e06b23127ea8c3d80aec9141077149556e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4210000000000000000000000000000000000000000000000000000000000000000ffffffff000102000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0502e8030102ffffffff0200204aa9d1010000232102c781355bd115fd37d04c6967e98c665b1bb32829f681989caa2758eebb4e0578ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000000");
        let decode: Result<Block, _> = deserialize(&block);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(2147483647));
        
        let block2 = hex!("000000801b2aeed9c15769abdce798148c0b425456479d884833512d298fdb5d827c00008952d46e1ad68112e9e1f726affa4d955f28dd90aa759f5a0098ea6934245b908116cf59ffff001fa9eb0000e965ffd002cd6ad0e2dc402b8044de833e06b23127ea8c3d80aec9141077149556e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4210000000000000000000000000000000000000000000000000000000000000000ffffffff000102000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0502e8030102ffffffff0200204aa9d1010000232102c781355bd115fd37d04c6967e98c665b1bb32829f681989caa2758eebb4e0578ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000000");
        let decode2: Result<Block, _> = deserialize(&block2);
        assert!(decode2.is_ok());
        let real_decode2 = decode2.unwrap();
        assert_eq!(real_decode2.header.version, Version(-2147483648));
    }

    #[test]
    fn validate_pow_test() {
        let some_header = hex!("0300002097d2cb7dbeb2c1a01e60870a3e48ce8e832bdc0d00cfa8603dae648862b50000f201aacca12a387a7c0bc18f7bc1b33dea5d828fcead35807cc7b3672a1fbc545f37b259ffff001f6d430000e965ffd002cd6ad0e2dc402b8044de833e06b23127ea8c3d80aec9141077149556e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4210000000000000000000000000000000000000000000000000000000000000000ffffffff00");
        let some_header: Header = deserialize(&some_header).expect("Can't deserialize correct block header");
        assert_eq!(some_header.validate_pow(some_header.target()).unwrap(), some_header.block_hash());

        // test with zero target
        match some_header.validate_pow(Target::ZERO) {
            Err(BlockBadTarget) => (),
            _ => panic!("unexpected result from validate_pow"),
        }

        // test with modified header
        let mut invalid_header: Header = some_header;
        invalid_header.version.0 += 1;
        match invalid_header.validate_pow(invalid_header.target()) {
            Err(BlockBadProofOfWork) => (),
            _ => panic!("unexpected result from validate_pow"),
        }
    }

    #[test]
    fn compact_roundrtip_test() {
        let some_header = hex!("0300002097d2cb7dbeb2c1a01e60870a3e48ce8e832bdc0d00cfa8603dae648862b50000f201aacca12a387a7c0bc18f7bc1b33dea5d828fcead35807cc7b3672a1fbc545f37b259ffff001f6d430000e965ffd002cd6ad0e2dc402b8044de833e06b23127ea8c3d80aec9141077149556e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4210000000000000000000000000000000000000000000000000000000000000000ffffffff00");

        let header: Header = deserialize(&some_header).expect("Can't deserialize correct block header");

        assert_eq!(header.bits, header.target().to_compact_lossy());
    }

    #[test]
    fn soft_fork_signalling() {
        for i in 0..31 {
            let version_int = (0x20000000u32 ^ 1<<i) as i32;
            let version = Version(version_int);
            if i < 29 {
                assert!(version.is_signalling_soft_fork(i));
            } else {
                assert!(!version.is_signalling_soft_fork(i));
            }
        }

        let segwit_signal = Version(0x20000000 ^ 1<<1);
        assert!(!segwit_signal.is_signalling_soft_fork(0));
        assert!(segwit_signal.is_signalling_soft_fork(1));
        assert!(!segwit_signal.is_signalling_soft_fork(2));
    }
}

#[cfg(bench)]
mod benches {
    use super::Block;
    use crate::EmptyWrite;
    use crate::consensus::{deserialize, Encodable, Decodable};
    use test::{black_box, Bencher};

    #[bench]
    pub fn bench_stream_reader(bh: &mut Bencher) {
        let big_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");
        assert_eq!(big_block.len(), 1_381_836);
        let big_block = black_box(big_block);

        bh.iter(|| {
            let mut reader = &big_block[..];
            let block = Block::consensus_decode(&mut reader).unwrap();
            black_box(&block);
        });
    }

    #[bench]
    pub fn bench_block_serialize(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        let block: Block = deserialize(&raw_block[..]).unwrap();

        let mut data = Vec::with_capacity(raw_block.len());

        bh.iter(|| {
            let result = block.consensus_encode(&mut data);
            black_box(&result);
            data.clear();
        });
    }

    #[bench]
    pub fn bench_block_serialize_logic(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        let block: Block = deserialize(&raw_block[..]).unwrap();

        bh.iter(|| {
            let size = block.consensus_encode(&mut EmptyWrite);
            black_box(&size);
        });
    }

    #[bench]
    pub fn bench_block_deserialize(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        bh.iter(|| {
            let block: Block = deserialize(&raw_block[..]).unwrap();
            black_box(&block);
        });
    }
}
