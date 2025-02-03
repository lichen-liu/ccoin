mod client;

fn main() {
    let my_chain = client::local_chain::LocalChain::empty();
    
    println!("Hello, world!");
}
