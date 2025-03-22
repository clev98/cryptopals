#![warn(clippy::all, clippy::pedantic)]
#![warn(clippy::unwrap_used)]

use reqwest::blocking;
use std::time::{Duration, SystemTime};
use hex;

fn make_sha1_hmac_request(
    domain: &str, 
    port: u16, 
    file: &str, 
    hmac: &[u8; 20]) -> bool
{
    let uri = format!(
        "http://{}:{}/test?file={}&signature={}",
        domain,
        port,
        file,
        hex::encode(&hmac));
    let response = match blocking::get(uri) {
        Ok(resp) => resp,
        Err(err) => panic!("Error: {}", err)
    };

    response.status().is_success()
}

fn try_mac(
    domain: &str, 
    port: u16, 
    file: &str, 
    repetitions: u8,
    hmac: &[u8; 20]) -> u128
{
    let mut times: Vec<Duration> = Vec::new();

    for _ in 0..repetitions {
        let start = SystemTime::now();
        let result = make_sha1_hmac_request(domain, port, file, hmac);
        let end = SystemTime::now();

        if result {
            println!("HMAC: {:?}", hmac);
        }

        let duration = end.duration_since(start).unwrap();
        times.push(duration);
    }

    let sum: Duration = times.iter().sum();
    
    sum.as_millis() / times.len() as u128
}

fn attack() -> () {
    let mut mac = [0u8; 20];
    let domain = "127.0.0.1";
    let port: u16 = 9001;
    let file = "file.txt";
    let reps = 2;

    for i in 0..20 {
        let mut times = [0u128; 256];

        for j in 0..=255 {
            let mut test_mac = [0u8; 20];
            test_mac.copy_from_slice(&mac);
            test_mac[i] = j;
            times[j as usize] = try_mac(&domain, port, &file, reps, &test_mac);
        }

        let best_time = times.iter().zip(0..=255).max_by(|x, y| x.0.cmp(y.0)).unwrap().1;
        mac[i] = best_time;
    }
}

fn main() {
    attack();
}
