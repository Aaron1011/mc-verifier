#![feature(stmt_expr_attributes)]
#![feature(proc_macro_hygiene)]
#![feature(async_closure)]

use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::atomic::Ordering;


use futures::StreamExt;
use std::alloc::System;

use json::object;

use image::GenericImageView;
use mc_verifier::{McVerifier, created_date};

use termimage;
use image;

use hyper_tls::HttpsConnector;
use hyper::Client;

use futures::future;

use std::sync::Arc;

use atomicbox::AtomicOptionBox;
use std::sync::RwLock;
use futures_async_stream::for_await;

#[global_allocator]
static A: System = System;

#[tokio::main]
async fn main() {
    env_logger::init();


    let addr = "127.0.0.1:25567".parse::<SocketAddr>().unwrap();
    println!("Running server on {:?}", addr);

    let verifier = McVerifier::start(addr).await;
    let (stream, canceller) = verifier.into_inner();
    let canceller = Arc::new(AtomicOptionBox::new(Some(Box::new(canceller))));
    let start_date_cache = Arc::new(RwLock::new(HashMap::new()));

    #[for_await]
    for user_data in stream {
        let canceller = canceller.clone();
        let start_date_cache = start_date_cache.clone();
        tokio::spawn(async move {
            let start_date_cache = start_date_cache.clone();

            println!("Main callback!");
            let user_data = user_data.expect("Error resolving user!");
            println!("Main: Got user {:?}", user_data.user.name);


            let https = HttpsConnector::new().unwrap();
            let mut client = Client::builder().build::<_, hyper::Body>(https);
            let uri  = format!("https://minotar.net/body/{}/100.png", user_data.user.id.to_simple()).parse().unwrap();

            println!("Requesting: {:?}", uri);


            let res = client.get(uri).await.unwrap();
            let body = res.into_body();
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

            let username = &user_data.user.name;

            // This is fairly annoying. Ideally, this expression would be inline in the 'if let'
            // expression: e.g. 'if let Some(data) = start_date_cache.read().unwrap().get(username).cloned()'
            // Unfortunately, the temporary 'RwLockReadGuard' returned by 'read' would not be
            // dropped until after the *entire* if/else block finished - which means that it could
            // live across the 'await' point.
            // This is necessary to force the read guard to be dropped early
            let get_entry = || {
                start_date_cache.read().unwrap().get(username).cloned() 
            };

            let start_date = if let Some(date) = get_entry() {
                date
            } else {
                let date = created_date(&mut client, username.clone()).await.unwrap();
                let mut cache_mut = start_date_cache.write().unwrap();
                cache_mut.insert(username.clone(), date);
                drop(cache_mut);
                date
            };

            println!("Start date: {:?}", start_date);

            let user = user_data.user;

            let message = format!("Successfully authenticated:\n{}\nUUID {}\nCreation date: {}", user.name, user.id, start_date);

            user_data.disconnect.send(object! {"text" => message }.to_string()).unwrap();

            canceller.swap(None, Ordering::SeqCst).expect("Already tried to shutdown the server!").cancel();
        });
    }
}
