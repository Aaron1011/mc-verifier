#![feature(async_await)]

use std::net::SocketAddr;

use futures::StreamExt;
use mc_verifier::server_stream;
use std::alloc::System;

use image::GenericImageView;

use termimage;
use image;

use hyper_tls::HttpsConnector;
use hyper::Client;

use mc_verifier::ExecutorCompat;

use futures::future;
use futures::compat::{Future01CompatExt, Stream01CompatExt, Compat};
use futures::prelude::*;


#[global_allocator]
static A: System = System;

fn main() {
    env_logger::init();

    let addr = "127.0.0.1:25567".parse::<SocketAddr>().unwrap();
    println!("Running server on {:?}", addr);
    tokio::run(server_stream(addr, Box::new(|_addr| {
        false
    })).then(async move |user| {
        println!("Main callback!");
        let user = user.expect("Error resolving user!");
        println!("Main: Got user {:?}", user.name);


        let https = HttpsConnector::new(4).unwrap();
        // TODO: re-enable keep-alive when Hyper is using std-futures tokio
        let client = Client::builder().keep_alive(false).executor(ExecutorCompat).build::<_, hyper::Body>(https);
        let uri  = format!("https://minotar.net/body/{}/100.png", user.id.to_simple()).parse().unwrap();

        println!("Requesting: {:?}", uri);


        let res = client.get(uri).compat().await.unwrap();
        let body = res.into_body().compat();
        let folded = body.fold(vec![], |mut acc, chunk| {
                acc.extend_from_slice(&chunk.unwrap().as_ref());
                future::ready(acc)
        });

        let data: Vec<u8> = folded.await;

        std::fs::write("blah_skin.png", &data).unwrap();

        let skin_front = image::load_from_memory_with_format(&data, image::ImageFormat::PNG).expect("Failed to decode image!");
        let term_dims = term_size::dimensions().unwrap();
        let term_dims = (term_dims.0 as u32, term_dims.1 as u32);
        let new_s = termimage::ops::image_resized_size(skin_front.dimensions(), term_dims, true);
        let resized = termimage::ops::resize_image(&skin_front, new_s);
        termimage::ops::write_ansi_truecolor(&mut std::io::stdout(), &resized);

    }).for_each(|_| future::ready(())));
}
