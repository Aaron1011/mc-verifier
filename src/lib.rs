extern crate serde;

use ozelot::Server;

use tokio::prelude::*;
use tokio::io::copy;
use tokio::net::TcpListener;

pub mod packet;

struct ClientFuture {
    // The naming is a little weird - a 'Server'
    // struct represents the server's view of a single
    // client connection
    client: Server
}

//impl Future for ClientFuture {
//}

fn main() {
    //let a: crate::packet::Packet = panic!();
    /*let addr = "127.0.0.1:25567".parse().unwrap();
    let listener = TcpListener::bind(addr).expect("Unable to bind TCP listener!");

    let tcp_server = listener.incoming()
        .map_err(|e| eprintln!("accept failed = {:?}", e))
        .for_each(|sock| {
            
        });*/
    //let server = Server::from(TcpStream::
    //println!("Hello, world!");
}
