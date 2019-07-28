use hyper::Client;
use uuid::Uuid;
use chrono::{NaiveDateTime, DateTime, Utc};
use futures::future;
use hyper::StatusCode;
use futures::future::FutureExt;
use hyper::client::connect::Connect;
use futures::compat::Future01CompatExt;
use futures::select;
use std::pin::Pin;

use hyper::Response;
use hyper::Body;

use std::future::Future;


// Based on https://gist.github.com/jomo/be7dbb5228187edbb993
pub async fn created_date<T: Connect + Sync + 'static>(client: &mut Client<T>, name: String) -> Result<DateTime<Utc>, Box<std::error::Error + Send>> {
    let mut start = 1263146630; // notch sign-up;
    let mut end = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

    let check = |name, time| {
        println!("Checking: {:?}", time);
        let boxed: Box<dyn Send + Future<Output = Result<Response<Body>, Box<std::error::Error + Send>>>> = Box::new(client
            .get(format!("https://api.mojang.com/users/profiles/minecraft/{}?at={}", name, time).parse().unwrap())
            .map(|r| r.map_err(|e| Box::new(e) as Box<std::error::Error + Send>)));
        Pin::from(boxed)
    };

    let calc_mid = |start, end| {
        start + ((end - start) / 2)
    };

    let mut cur_fut = check(&name, calc_mid(start, end)).fuse();

    loop {
        if start == end {
            println!("Finished!");
            return Ok(DateTime::from_utc(NaiveDateTime::from_timestamp(start as i64, 0), Utc))
        }
        let mid = calc_mid(start, end);
        let mut left_fut = check(&name, calc_mid(start, mid)).fuse();
        let mut right_fut = check(&name, calc_mid(mid + 1, end)).fuse();

        //let res = cur_fut.await?;


        let mut left_done = None;
        let mut right_done = None;

        loop {
            select! {
                cur_res = cur_fut => {
                    if cur_res?.status() == StatusCode::OK {
                        end = mid;
                        cur_fut = left_done.unwrap_or(left_fut);
                    } else {
                        start = mid + 1;
                        cur_fut = right_done.unwrap_or(right_fut);
                    }
                    println!("Resolved: {}", calc_mid(start, end));
                    break;
                },
                left_res = left_fut => {
                    println!("Got left future!");
                    left_done = Some(Pin::from(Box::new(future::ready(left_res)) as Box<dyn Send + Future<Output = _>> ).fuse());
                }
                right_res = right_fut => {
                    println!("Got right future!");
                    right_done = Some(Pin::from(Box::new(future::ready(right_res)) as Box<dyn Send + Future<Output = _>> ).fuse());
                }
            }
        }
    }
}
