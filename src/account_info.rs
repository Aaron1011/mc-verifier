use chrono::{NaiveDateTime, DateTime, Utc};
use futures::future;
use futures::future::FutureExt;
use futures::select;
use std::pin::Pin;

use std::future::Future;
use failure::Error;
type Result<T> = std::result::Result<T, Error>;
type DateResult = Result<DateTime<Utc>>;

// Based on https://gist.github.com/jomo/be7dbb5228187edbb993
pub async fn created_date(name: String) -> DateResult {
    let mut start = 1263146630; // notch sign-up;
    let mut end = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();

    let check_inner = async move |name, time| {
        println!("Checking: {:?}", time);

        let url = format!("https://api.mojang.com/users/profiles/minecraft/{}?at={}", name, time);
        Ok(reqwest::get(&url).await?)
    };

    let check = |name, time| {
        Pin::from(Box::new(check_inner(name, time)) as Box<dyn Send + Future<Output = Result<reqwest::Response>>>)
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
                    if cur_res?.status() == reqwest::StatusCode::OK {
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
