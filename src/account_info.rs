use hyper::Client;
use uuid::Uuid;
use chrono::{NaiveDateTime, DateTime, Utc};
use futures::future;
use hyper::StatusCode;
use hyper::client::connect::Connect;
use futures::compat::Future01CompatExt;

// Based on https://gist.github.com/jomo/be7dbb5228187edbb993
pub async fn created_date<T: Connect + Sync + 'static>(client: &mut Client<T>, name: String) -> Result<DateTime<Utc>, Box<std::error::Error>> {
    let mut start = 1263146630; // notch sign-up;
    let mut end = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

    let check = |name, time| {
        println!("Checking: {:?}", time);
        client
            .get(format!("https://api.mojang.com/users/profiles/minecraft/{}?at={}", name, time).parse().unwrap())
            .compat()
    };


    loop {
        if start == end {
            return Ok(DateTime::from_utc(NaiveDateTime::from_timestamp(start as i64, 0), Utc))
        }
        let mid = start + ((end - start) / 2);
        let res = check(&name, mid).await?;
        if res.status() == StatusCode::OK {
            end = mid;
        } else {
            start = mid + 1;
        }
    }
}
