use sha2::{Sha256, Digest};
use std::borrow::Cow;

pub trait HexStr {
    fn to_hex_str(&self) -> String;
    fn from_hex_str(hex_str: &str) -> Result<Self, Box<dyn std::error::Error>> where Self: Sized;
}

impl HexStr for Vec<u8> {
    fn to_hex_str(&self) -> String {
        hex::encode(self)
    }

    fn from_hex_str(hex_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = hex::decode(hex_str)?;
        Ok(bytes)
    }
}

pub trait AsBytes {
    fn as_bytes(&self) -> Cow<'_, [u8]>;
}

pub trait Sha256Digest {
    fn to_sha256(&self) -> Sha256DigestVal;
}

impl <T: AsBytes> Sha256Digest for T {
    fn to_sha256(&self) -> Sha256DigestVal {
        Sha256DigestVal::digest_from_data(&self.as_bytes())
    }
}

pub struct PublicKey(pub String);

impl AsBytes for PublicKey {
    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.0.as_bytes())
    }
}

pub struct SignatureVal(pub Vec<u8>);

impl AsBytes for SignatureVal {
    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self.0)
    }
}

impl HexStr for SignatureVal {
    fn to_hex_str(&self) -> String {
        self.0.to_hex_str()
    }

    fn from_hex_str(hex_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = Vec::<u8>::from_hex_str(hex_str)?;
        Ok(SignatureVal(bytes))
    }
}

pub struct Sha256DigestVal(pub Vec<u8>);

impl HexStr for Sha256DigestVal {
    fn to_hex_str(&self) -> String {
        self.0.to_hex_str()
    }

    fn from_hex_str(hex_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = Vec::<u8>::from_hex_str(hex_str)?;
        Ok(Sha256DigestVal(bytes))
    }
}

impl Sha256DigestVal {
    pub fn digest_from_data(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Sha256DigestVal(hasher.finalize().to_vec())
    }
}

impl AsBytes for Sha256DigestVal {
    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self.0)
    }
}

pub struct CoinVal(u64);

impl AsBytes for CoinVal {
    fn as_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.0.to_be_bytes().to_vec())
    }
}

pub struct TxContent {
    from: PublicKey,
    to: PublicKey,
    amount: CoinVal,
}

impl AsBytes for TxContent {
    fn as_bytes(&self) -> Cow<'_, [u8]> {
        let mut bytes = Vec::new();
        bytes.extend(self.from.as_bytes().as_ref());
        bytes.extend(self.to.as_bytes().as_ref());
        bytes.extend(self.amount.as_bytes().as_ref());
        Cow::Owned(bytes)
    }
}

pub struct Tx {
    content: TxContent,
    signature: SignatureVal
}

impl AsBytes for Tx {
    fn as_bytes(&self) -> Cow<'_, [u8]> {
        let mut bytes = self.content.as_bytes().to_vec();
        bytes.extend(self.signature.as_bytes().as_ref());
        Cow::Owned(bytes)
    }
}

pub struct BlockContent {
    block_id: u64,
    transactions: Vec<Tx>,
    miner: PublicKey,
    miner_reward: CoinVal,
    nounce: u64,
    prev_block: Sha256DigestVal,
}

impl AsBytes for BlockContent {
    fn as_bytes(&self) -> Cow<'_, [u8]> {
        let mut bytes = Vec::new();
        bytes.extend(self.block_id.to_be_bytes());
        for tx in &self.transactions {
            bytes.extend(tx.as_bytes().as_ref());
        }
        bytes.extend(self.miner.as_bytes().as_ref());
        bytes.extend(self.miner_reward.as_bytes().as_ref());
        bytes.extend(self.nounce.to_be_bytes());
        bytes.extend(self.prev_block.as_bytes().as_ref());
        Cow::Owned(bytes)
    }
}

pub struct Block {
    content: BlockContent,
    hash: Sha256DigestVal
}

impl AsBytes for Block {
    fn as_bytes(&self) -> Cow<'_, [u8]> {
        let mut bytes = self.content.as_bytes().to_vec();
        bytes.extend(self.hash.as_bytes().as_ref());
        Cow::Owned(bytes)
    }
}