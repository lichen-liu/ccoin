use sha2::{Sha256, Digest};

pub struct PublicKey(String);

pub struct SignatureVal(String);

pub struct HashVal([u8; 32]);

pub struct CoinVal(u64);

pub struct TxContent {
    from: PublicKey,
    to: PublicKey,
    amount: CoinVal,
}

impl TxContent {
    pub fn to_sha256(&self) -> HashVal {
        let mut hasher = Sha256::new();

        hasher.update(self.from.0.as_bytes());
        hasher.update(self.to.0.as_bytes());
        hasher.update(self.amount.0.to_be_bytes());

        HashVal(hasher.finalize().into())
    }
}

pub struct Tx {
    content: TxContent,
    signature: SignatureVal
}

pub struct BlockContent {
    block_id: u64,
    transactions: Vec<Tx>,
    miner: PublicKey,
    miner_reward: CoinVal,
    nounce: u64,
    prev_block: HashVal,
}

pub struct Block {
    content: BlockContent,
    hash: HashVal
}