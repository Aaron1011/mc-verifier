use std::net::SocketAddr;

use futures::StreamExt;
use mc_verifier::server_stream;
use std::alloc::System;

use futures::FutureExt;

#[global_allocator]
static A: System = System;

fn main() {
    let addr = "127.0.0.1:25567".parse::<SocketAddr>().unwrap();
    println!("Running server on {:?}", addr);
    tokio::run(server_stream(addr, Box::new(|_addr| {
        false
    })).for_each(|user| {
        println!("Main: Got user {:?}", user);
        futures::future::ready(())
    }));
}
