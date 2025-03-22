#![warn(clippy::all, clippy::pedantic)]
#![warn(clippy::unwrap_used)]

use std::{
    {thread, time},
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use warp::{
    http::{Response, StatusCode},
    Filter,
};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use digest::CtOutput;
use hmac::{Hmac, Mac};
use hex;

type HmacSha1 = Hmac<Sha1>;

#[derive(Deserialize, Serialize)]
struct FileSignature {
    file: String,
    signature: String,
}

fn insecure_compare(left: &[u8], right: &[u8], sleep: u64) -> bool {
    if left.len() != 20 || right.len() != 20 { 
        return false;
    }

    let millis = time::Duration::from_millis(sleep);

    for i in 0..left.len() {
        if left[i] != right[i] {
            return false;
        }

        thread::sleep(millis);
    }

    true
}

fn get_sha1_hmac(key: &[u8; 16], path: &str) -> CtOutput<HmacSha1> {
    let contents = fs::read(path).expect("Failed to read file");
    let mut mac = HmacSha1::new_from_slice(key).expect("Failed to create HMAC");
    mac.update(&contents);
    mac.finalize()
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let key = b"YELLOW SUBMARINE";

    let test = warp::get()
        .and(warp::path("test"))
        .and(warp::query::<FileSignature>())
        .map(|p: FileSignature| {
            let mut built_resp = Response::new("");
            let compute = get_sha1_hmac(key, &p.file);
            println!("{:?} {:02X?}", p.signature, compute.clone().into_bytes());
            let decoded_sig = hex::decode(p.signature).expect("Decoding signature failed");
            if insecure_compare(&decoded_sig, &compute.into_bytes()[..], 50) {
                *built_resp.status_mut() = StatusCode::OK;
            } else {
                *built_resp.status_mut() = StatusCode::NOT_FOUND;
            }
            built_resp
        });

    warp::serve(test)
        .run(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9001))
        .await;
}
