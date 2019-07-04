#![feature(async_await)]

use std::net::SocketAddr;

use futures::StreamExt;
use mc_verifier::server_stream;
use std::alloc::System;

use reqwest::r#async::{Chunk, Client};
use termimage;
use image;

use mc_verifier::ExecutorCompat;

use futures::future;
use futures::compat::{Future01CompatExt, Stream01CompatExt, Compat};
use futures::prelude::*;


#[global_allocator]
static A: System = System;

fn main() {
    let addr = "127.0.0.1:25567".parse::<SocketAddr>().unwrap();
    println!("Running server on {:?}", addr);
    tokio::run(server_stream(addr, Box::new(|_addr| {
        false
    })).then(async move |user| {
        println!("Main callback!");
        let user = user.expect("Error resolving user!");
        println!("Main: Got user {:?}", user.name);


        let client = Client::new();
        let uri  = format!("https://minotar.net/body/{}/100.png", user.id);//.parse().unwrap();

        println!("Requesting: {:?}", uri);


        let res = client.get(&uri).send().compat().await.unwrap();
        let body = res.into_body().compat();
        let folded = body.fold(vec![], |mut acc: Vec<u8>, chunk: Result<Chunk, reqwest::Error>| {
                acc.extend_from_slice(&chunk.unwrap().as_ref());
                println!("Acc: {:?}", acc);
                let ready: futures::future::Ready<Vec<u8>> = future::ready(acc);
                ready
        });

        let data: Vec<u8> = folded.await;

        std::fs::write("blah_skin.png", &data).unwrap();

        let skin_front = image::load_from_memory_with_format(&data, image::ImageFormat::PNG).expect("Failed to decode image!");
        termimage::ops::write_ansi_truecolor(&mut std::io::stdout(), &skin_front);

    }).for_each(|_| future::ready(())));
}
