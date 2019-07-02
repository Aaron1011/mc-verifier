use std::net::SocketAddr;

use mc_verifier::server_future;
use std::alloc::System;

use futures::FutureExt;

#[global_allocator]
static A: System = System;

fn main() {
    let addr = "127.0.0.1:25567".parse::<SocketAddr>().unwrap();
    println!("Running server on {:?}", addr);
    tokio::run(server_future(addr, |addr| {
        // Keep accepting clients
        false
    }).map(|_| ()));
}
