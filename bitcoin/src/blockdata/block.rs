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

    use crate::hashes::hex::FromHex;
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

    // Qtum
    #[test]
    fn qtum_block_qtum_specific_fields_test() {
        let block = hex!("00000020225af41883428d8625ee48c1a9ad2c097ea308d8f3b508f0df334a42723687db5c74f53ef806efc12b5debfe7c5becc26c899bcd476efeca50e389a63cd7283a10faf25d8b490c1a000000007330d78461257d81e0a2d02c3b294280052fe1b95b0e9770000157e0b6a997d424114d8a88aef16152b829aaecc2aa2b00db8fea4a0b27a6f120f43e60769e4c4a98cf7c5461f9c2262fb992137a5a6554ad9a801c1dd940667e7c81feafd5a70100000046304402204449e9deca0e42bc0399bbbff2e343c721c33f294ae85ab8e665f6f90ea4e5b102201c986da6111547df7422f70ffa5e3523264990b0e62c4ac285e7cf245ff4a58702020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0503f6a80700ffffffff020000000000000000000000000000000000266a24aa21a9ed598bdca4eab6001d5753ba33e9a50b1986649f4b477948b5f761decd6b742b4e0120000000000000000000000000000000000000000000000000000000000000000000000000020000002e4a98cf7c5461f9c2262fb992137a5a6554ad9a801c1dd940667e7c81feafd5a70100000048473044022039dc3badebb61629a9626ce520a946ce0514f1222f4ee13f20dfdb85a004587d022067b3719fd80b1f26afe39fd2cc70476f73668b5b9ad0ae20e8e8e7def89f414701ffffffff0656ba6da45687934e447a338b172b7222f1bb7b8963bb4a4c8cfc6031288f73020000006a47304402207bee2998cfbaac43f1a2f28938071e48e14ee78743fb960438935f526b89e94f02201a879f7abe476760208af97cbea82ccc88f8e81f5c7dc2f8caa4012dd10a1ce3012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffffb9770d9c20d4090790cb95746af893b0fc4f60849b00f8c83bd63694a47dcdb3030000006a473044022046342e6a2052b53cae117e7a8f42201cb38e860ddb28a9334874e83131f3479a02201f86a3a677645cf3cd4a0f732858678200e3e515124fb7e4a22d366e6303fa21012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff914440f095a5e5685d5d6c2c13074e9aa1fa5e6e1bef1fcf39b719f8f49313d0040000006a4730440220418cbaacc2e8a38119e987fb5f23c80a3ed0e7ce194f0f586bb26db5d405b976022026d04351fc4004e16fe919eaf63db166faa0243ccfbabe670b4f5b8ad9985458012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffffe2623d57c0fbfbb30b185d2e29ab68575488012fa88b6df39d083e66eb6e7be7050000006a4730440220431405590681e50e00780d8c09f97c2c30f57e86cf7349947eb7e9d8cfffa5050220768a7e66cf3641de13c4d60dc48c02adbf87d65600ebd8410ad497970d2ea85f012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff9b7ba4354b04adde91b8f47143dc070d07d4d76c7a8dff1cee2488464071c32e060000006a47304402204faea4738b3beb7c90bc001ba56045fe3b3c7c5bd0733bb815d69f00cda7c8d8022049c4eb5bfb96f51ebf064bbbbe34f8e189c83ac30154814b21d9567048710e9e012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff23b717014a70b9868de2229e1d44a9a82fd2cecf5a61fa1f79fd310edee87d5e070000006a47304402204261f7dc2e7cb39b4778405ce8813b275dddf19581540af6c23191b8df26be2702204b9891e39f82236df906368ae071ecb3e91bf3011ee427ae760a21c28763c4af012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff2419a5ad55eecb7fd99ed3881d3ddf12aabdb13d7f2f0569136160c0fad2f451080000006a4730440220162b1cc57dfc71aef20a9b113cec66fafb08e80ee77b6d8804d11270e41e65680220594fc2ecdf8a5e84a4b206243ce155151d2e06e9464445b0104fca28ce8fff9e012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff0c7df3ec4cfb4ab70c6a269afd055313eb37c32140a2318874c541d45e8e12e00a0000006a47304402206e4e5430c31add322aff681eef6ac3745b985063dcadeb3af75b5c830d0f145b02205a79413dc8c39d801fdf69e85d2524128a095a0bb66036a6b34c3516c6defba1012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff78adcb8b9ec5e237cd423a6de5d53d73a4e121ae8d26091a8356bea4e402fc360a0000006a47304402207595aa29fdfed2370e4cde6dcde4c00b7510dd2ed15c3821b3830303261fe1e602202dba728263e3087db03cd8e5d4de6eb7dd2425e0d4bd6e5609c0ef0d854060bc012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff1575e1f70907c85867e59f2be929286f057896d2768dd6d17682d54b0046504d020000006a4730440220488719e88a2eea0b11bd9388448d53e8c5e51bcf66c887097ea73a2539c08b7e02201c4e003b0a70d24f99ff08ff948a9b49c1438a986f4d2308847f40a49d69f78b012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff9f9cc75d74ebdad6292d11bb3372beb11164439ec6bbd49627275c056152735c030000006a47304402200ad76b3f1b1638640bbce38e1c983154bb16c54b8ff989ebaa8739110e3d0ee702201debd4ddb816bdc486a47eba9721a3d035b354507b800257220ba0ed38d2ad62012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff9ebc8829cd32158f95d428ac743140063786480b58fc37f8e90a01f120d586ff040000006a4730440220195b1d80800963ea64207ef70d74f0e4698c316c6b2acfc95b45b160e921ee75022041b5c3685c29d1936b1b668c49382e9ad8e45e9ddbe52d6f6af8b97c3797eeed012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffffc6f172383a343d6c786132ebd6268ab1b7bb3bdd085bb1c4150c7f504da7bfc6050000006a4730440220499f14e284ccfc5ce7fa21a0a146ea394efbe7f4f5ee74a7861f0f4b626b8dd7022065d8a15b8621da175b9acc0601fdda0eef6e0ccffd16015c184d4e1843643085012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff3e5da1c26e2a722681fa369cc30694713822c0a2e3fc5cffdce940bfd028f96e070000006a473044022029ad50476fbcde9493b48254e74542452921f73626692364730e0f81077d5d4f02204136c81332550e654b3dd6a7cd2f96931362e7d8b8865f57df01c917e1c6d6fa012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff55af615ccdf28d26e9e10398af783a75607f70873d9ef4d7f9e1bd0a66aa3938070000006a473044022018e2a035a1074cc765f3be03125a69acb24a2f54baaac8e99afcc3ffc3190b0c022069d5a3d7e8354b7a2e86715f91284a5e671f57652a996888a4ab1ab2c0b08d11012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffffeb3aee22526e1681d2855839fe40091282280ea4b8dee1c1159220a663e16081080000006a47304402205a7e2fa65f7c8caabbb106d4857d908a64d9542140b597e7930e48945fb9fb6702203c1e2a5ec398616a38cde44299073fc6fc12d2f5710a66063096c7fee34f9562012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff5b0c9d5d3a94c00439ee94c9b7c9e393b59df0ecf406b950af6296d2326d0b91090000006a4730440220739419fb2ad5c43570ffa620731c9f6cb5c885fe016ab00cfddd447168135c0402200db0a41b9ab260c680341c7b44fb20644a17315e98a0ad4bd79efe700ad90249012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff6f93ec37f8a2e7e69579c7b82b9895d07e65fc8d8a3dad77a098a9236b085e050a0000006a47304402207d135e57195a0d8a48308afd87e6b68400972dbe94ae40e41e645b2bc314e75702200a7e9fcdfd24e16c26d30dc66c0065f3cba803dbd5aa86288768e584363487c0012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff44bd996d191465d58a93ae9d6f4a113760b3639d002ef302073b857c1ebe40d7020000006a473044022010d34441a2a85e3d779a328aa1eed8d35ea97dbe583d8bad8aeacf76bc1392830220795f3c5cd22d3e283c5a22fd5a88b055d6837b6262362bb319a16ea96d4662f8012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffffc8beb56d5c6e320d8436a91ae6b662d56fcdee0cd89ba3d44eb2032123f969a6030000006a47304402206117568d43ee9918df5c6fce0affbc37f40b3de99dc9d9841797765ec2ed989b02202100252dede51805a0a4f04dad08d9789affd3de4bc2e37a5367fccd35ac6cfb012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffffa5b05d09bd054af12716dc8e71fc628177ec9a2fce10ee4c491838c6f6fade24040000006a4730440220579e8e7db281a259bd9dad2b82e99cd9f5b5ebb2f8710ef3a27c1f67a37fec1f022073f967969ee8a7f6b40eb9e3bc166dc3407ef02f88fcc2db21aff3965e2bcaae012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff16702d37e9276343eb8ad0279c5a174082655e4143475faf2c96635fd9e2e62c050000006a473044022005acb4ea0c115b9ac8b17746f7a4f30a8360881ebb7c0df034dbaa1e5ca34c24022054d9b635317adc8ebca24c626122e68a498e29636c24c634cc69fa04f64d70ff012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffffbf4949f91f8f9cd002b2796d06a528e129e6fb424e33d17e387e4824b537f44a060000006a4730440220234588f37a16d9ac02317140cc19bd24d39052e903a3ebb300e216a45816f2fc022048218257d514f5f7b0c7900c3227ec60e1b8d18a413ab2d3c512a7d74584d236012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff07d2713bf1d1edf15437af9bad29108cc24eca727953afd9cd8f80c9e7f1cf4b070000006a4730440220784c66975f92e72ebe359d85df5350ae9f7cc199aa979a29a4227d949b302a75022027d84fdb5611810869961481a98cc4f26422d98e647fe0ec02aa563dc672e68e012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff429dac3a6ccff7e3f5cce7299fbaf1766f37c6d59bcfcd373ef5ee54d1b29758090000006a47304402203cad91477c243906d978e1b1a5953258ae2ebc77d3606f83f66ba873aa05116002201c3b497283b4e58908fa09c4a6e3571b08f0bf71d82b1ccf3c129300db2bd498012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff5a98a03ba70af7aa3abc2643df356d4366ed5cdd51a7002bfb39e2b155a5c350090000006a473044022045aa1537c61bd311fd65727cc692fbe0bd677cf2ec08514d3081714a2e8b75a30220132157cee714e3e046f5ef3e1e65d121afcff0d78dbce6f186c2e040dd9a8610012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff57daba897a3575fe9a019ede4770bb5da8d6108c974d8a4c8a3e9fc3dfd773800a0000006a4730440220580ecda06fe028033b620a146dd44eed34e4130ec56f79bec8cfdf98c198333d0220325f56f78220d47124a6b8f24d4460ca5ac10bb865603103fa241c2fc01c63fe012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff823ecc0cd83123687fe22b03770db7d20a3cb583375b4eda98cc0620a6736068020000006a47304402200fd13aa6c59d2d6b3e85c80816d19b2ca1b23acd592d8afa3ed055b5862502040220379e29cb9c488476531a9ec6c1d42fde72b1d171a11d70b6f298fb1fb97c7c6b012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff7eccb474539a0d0bb048b6742dcfec72db68483163bd24589f38f9fd7c1a61a0040000006a4730440220592edec677063585248c189fb2d16927d915b00a8339eb352dd7169e080c4990022066dc6d1855b5b446cfe0f2703264418032d8b848b8a7b571f5649f3e4fbc3b55012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffffa61ee3143c7a42627ac3c78ba6ab94333d993fa3d5c333110c54251842d8f8cd040000006a473044022057b669309b7e7e94ebb550e4f3670bba59453d5bed5be8a3ca77125ed8a791380220587282844a50d09e943d7f014eeb19074defbd1efa6c92cd90fda769698e2208012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff07d38e4049cd649dec7c33ffbf1240aefb7602f31f74ac2fb4d6aa2fc7c78faf050000006a4730440220461f3d6bcc5c52ed6414d46eaa8de5af906a1a78444fd4c875367402e55750b602207a775e9fbc0af4d0c6c79d66ba4011745b3e8973351c73c92ba6ea199f89caf2012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff93a9a94dd19b48154763a031e17d29f036721a91213f349b7b771304097fb261070000006a473044022057a5da01e2cbdf58d97c0707d99fbfb3320c5c5f9cbf237e4b537cd50890058d022049cf0b5508d778f949180ea389d783fa9e983621e9aaa2e689e908a2e93ecc80012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffffe42f44ba36b72c156b4784f74399216187f41692eae6407f19a5cc9d38808dc0070000006a47304402206a017338f949824d4945b88423093b25cfdcd115de408c7f6ec0179b781f0dec02204a2df0a12794e2c38ac4df183b8f760658227ae745fbc2464d6a1e3d72682795012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff452796732a6ff6e3569b7cfc2e8537f2c9633311d16856d0b57979392c22b76f080000006a4730440220607677e63146c133c0db66b709b641b12a67b26fd6e5339a95fe78c8653ce7e50220530f490dac05a9115a4a888f5f51978851545925b3fe42a157f061eb7fe090d4012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff77d9eea676bf78a1a0fc29a0118a61d7aea7ff8e73a39a16f56fdd9f73e5b98a090000006a4730440220149ae5655f1f2b1dcb8cf8b784a5adfcf7bb1c17681bf3ce411e74ec13d8bc2c022046b2cee5a96dcc5b8606c51ca77e50e95931e668401383dcd9481e1c46d01192012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff8ea751af1cd95069c806333840032ad9c5708ddd18fd1e7bb90af273649fcba4020000006a47304402207c35f824827d185d102f775e713e785f01635f10f81b0e7748c33ec4b40ac416022023c402a3ba75d506206b2ebd493088d4d3132cf4ade8ca5dd9291aa902cfc219012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff8ea751af1cd95069c806333840032ad9c5708ddd18fd1e7bb90af273649fcba40a0000006a4730440220506b6105fbfea10595fcfb042ae4d9c4645f990429eaa42b782c7984cd4cff1402207a76e9f439dbf815cff4a13e6882daad7ad1ab922f6e016b823cb4490c6e7ae4012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff6419c664a1ddea7ca9d83041bc3a7d6aa73b930b0894067116530c9436b3d855040000006a473044022015a38710dbd5230b2bdb21df625904162b6ec3b4de904315eb7c0ea9c11d43d80220755575c8fb9276ef9d3c5292c8f4103d9044632513fbb26c0ce272dd7c037756012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffffebda63b94e4d463547af24ccdd760051c0d399c5958858fbc96b83ed09d3da36040000006a47304402201d0f2f19a53c4e4349c64513d31dc5c462140be63653e12d1c525dfe18cc758e02201f449215beffdaafeb968ffb595e377a930ab292d66f941677292978f156c601012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff7bdca8abe1535daee04a06d36300005bcc20ef016290f616f62cff250422561e050000006a47304402206fdf234473645e9ed0c50a863526796cc637bbd9d2ae22f6854388510ce0a0c402207dc010fd9eeec8c7b4f0908040d5571bf9b8f435464c268ec944dad42e31f809012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506fffffffff5331ac5d8145a658af1e18ce191162678b4357f99813c7603accb9119d15b6b070000006a47304402205c5edec8a52797d04463d179b7491f19e6bbb0570e3c63dc86f24ac9b3b1b12302205118a6240ddca6d62c8775e5e8f89de5f92eaf26fc9cd67c03166c8a47cb3e2a012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffffcd5f12f63a98dfda76e1b081f18fb2ed9fc53ddaea78afd4da3b144f6bb7f040070000006a47304402207560e58c63790ad121e6ff48361c1fe4a52a72685ff1772702f3b3c14d3895cc022072d8092632c69e1f853368d4c4434d5b3156aee38ed8d9d3b3cc81ff1dd27b28012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff89aaa2416da4b2338988a5d6ebfc75ec81406d0235562f68684f7a71fa6af5d4080000006a473044022043a45e6846de5ec9dc8e25e871ec64e0115173e554736f36be84608c4488b4aa0220027a0f708222c023fefd8b57f6a8f7acce6abc368fdeedb8a05e7fb57c11b045012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff8ee2a5a09d05a6971cd728e07a63e1011da4a4efb9734792566a8d8e27fa3344090000006a4730440220267c2f1355f5a351a0df7c0b2b81238abf875cdad2ef3a223cee34f702ba297702204ea64584a9759461646d62ab3041cd7a78586a444c3ecb05f40567c69a610f1e012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff9b426640c4fcee5fba7561530ffec1a85c9e39cb533d15c26bade6b44cc6ff260b0000006a47304402202bcc5df73ddb318abcb86b198e8a64b62010c2cc1395208eb0e30c2cb0c43ffe02201d7dd3373b8cf9db857066831fe57e8fa5aded472d70448ad54cf710b3691b51012102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ffffffff0b00000000000000000034270d1a03000000232102ed405ca296cfed31cc47d563ef9850782a3dd746c5497fd9a96b5dc1844db506ac005a6202000000001976a9146c89a1a6ca2ae7c00b248bb2832d6f480f27da6888ac005a6202000000001976a914ac54019592bda61400df17e68a257857b8d901a088ac005a6202000000001976a914ac54019592bda61400df17e68a257857b8d901a088ac005a6202000000001976a9142e10fe88d6e075ad44a42f5c941599240aeba5fb88ac005a6202000000001976a914dd5336bf4a318c78dffb57b31483617a5924bd2388ac005a6202000000001976a914ac54019592bda61400df17e68a257857b8d901a088ac005a6202000000001976a9142e10fe88d6e075ad44a42f5c941599240aeba5fb88ac005a6202000000001976a914a1bd7f3b948aa9a77c6486ad5f1ebfe247fab4d488ac005a6202000000001976a914ac54019592bda61400df17e68a257857b8d901a088ac00000000");
        let decode: Result<Block, _> = deserialize(&block);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.hash_state_root.to_string(), "d497a9b6e057010070970e5bb9e12f058042293b2cd0a2e0817d256184d73073");
        assert_eq!(real_decode.header.hash_utxo_root.to_string(), "4c9e76603ef420f1a6270b4aea8fdb002baac2ecaa29b85261f1ae888a4d1124");
        assert_eq!(real_decode.header.prevout_stake.txid.to_string(), "a7d5affe817c7e6640d91d1c809aad54655a7a1392b92f26c2f961547ccf984a");
        assert_eq!(real_decode.header.prevout_stake.vout, 1);

        let signature = Vec::<u8>::from_hex("304402204449e9deca0e42bc0399bbbff2e343c721c33f294ae85ab8e665f6f90ea4e5b102201c986da6111547df7422f70ffa5e3523264990b0e62c4ac285e7cf245ff4a587").unwrap();
        assert_eq!(real_decode.header.signature, signature);
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
