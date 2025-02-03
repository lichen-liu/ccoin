use super::block;

pub struct LocalChain {
    blocks: Vec<block::Block>
}

impl LocalChain {
    pub fn empty() -> Self {
        Self {blocks: Vec::new()}
    }
}