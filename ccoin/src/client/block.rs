pub struct PublicKey(String);

pub struct SignatureVal(String);

pub struct HashVal(String);

pub struct CoinVal(u64);

pub struct Transaction {
    from: PublicKey,
    to: PublicKey,
    amount: CoinVal,
    signature: SignatureVal
}

pub struct Block {
    block_id: u64,
    transactions: Vec<Transaction>,
    miner: PublicKey,
    miner_reward: CoinVal,
    nounce: u64,
    prev_block: HashVal,
    hash: HashVal
}