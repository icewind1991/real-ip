//! Get the "real-ip" of an incoming request.
//!
//! This uses the "forwarded", "x-forwarded-for" or "x-real-ip" headers set by reverse proxies.
//!
//! ## Trusted proxies
//!
//! To stop clients from being able to spoof the remote ip, you are required to configure the trusted proxies
//! which are allowed to set the forwarded headers.
//!
//! Trusted proxies are configured as a list of [`IpNet`]s, which can be a single ip or an ip range.
//!
//! Note that if multiple forwarded-for addresses are present, which can be the case when using nested reverse proxies,
//! all proxies in the chain have to be within the list of trusted proxies.
//!
//! ## Examples
//!
//! A request originating from 192.0.2.1, being proxied through 10.10.10.10 and 10.0.0.1 before reaching our program
//!
//! ```
//! # use http::Request;
//! # use std::net::IpAddr;
//! # use real_ip::{real_ip, IpNet};
//! #
//! // in a real program this info would of course come from the http server
//! let incoming_ip = IpAddr::from([10, 0, 0, 1]);
//! let request = Request::builder().header("x-forwarded-for", "192.0.2.1, 10.10.10.10").body(()).unwrap();
//!
//! // the reverse-proxies in our network that we trust
//! let trusted_proxies = [
//!     IpAddr::from([10, 0, 0, 1]).into(),
//!     IpNet::new_assert(IpAddr::from([10, 10, 10, 0]), 24), // 10.10.10.0/24
//! ];
//! let client_ip = real_ip(request.headers(), incoming_ip, &trusted_proxies);
//! assert_eq!(Some(IpAddr::from([192, 0, 2, 1])), client_ip);
//! ```
//!
//! A request originating from 192.0.2.1, being proxied through 203.0.113.10 and 10.0.0.1 before reaching our program.
//! But 203.0.113.10 is not a trusted proxy, so we don't accept anything it added to the forwarded headers
//!
//! ```
//! # use http::Request;
//! # use std::net::IpAddr;
//! # use real_ip::{real_ip, IpNet};
//! #
//! let incoming_ip = IpAddr::from([10, 0, 0, 1]);
//! let request = Request::builder().header("forwarded", "for=192.0.2.1, for=203.0.113.10;proto=https").body(()).unwrap();
//!
//! let trusted_proxies = [
//!     IpAddr::from([10, 0, 0, 1]).into(),
//!     IpNet::new_assert(IpAddr::from([10, 10, 10, 0]), 24),
//! ];
//! let client_ip = real_ip(request.headers(), incoming_ip, &trusted_proxies);
//! assert_eq!(Some(IpAddr::from([203, 0, 113, 10])), client_ip);
//! ```

pub mod headers;

use crate::headers::{
    extract_forwarded_header, extract_real_ip_header, extract_x_forwarded_for_header,
};
use http::HeaderMap;
pub use ipnet::IpNet;
use itertools::Either;
use std::iter::{empty, once};
use std::net::IpAddr;

/// Get the "real-ip" of an incoming request.
///
/// See the [top level documentation](crate) for more usage details.
pub fn real_ip(headers: &HeaderMap, remote: IpAddr, trusted_proxies: &[IpNet]) -> Option<IpAddr> {
    let mut hops = get_forwarded_for(headers).chain(once(remote));
    let first = hops.next();
    let hops = first.iter().copied().chain(hops);

    'outer: for hop in hops.rev() {
        for proxy in trusted_proxies {
            if proxy.contains(&hop) {
                continue 'outer;
            }
        }
        return Some(hop);
    }

    // all hops were trusted, return the first one
    first
}

/// Extracts the ip addresses from the "forwarded for" chain from a request
///
/// Note that this doesn't perform any validation against clients forging the headers
pub fn get_forwarded_for(headers: &HeaderMap) -> impl DoubleEndedIterator<Item = IpAddr> + '_ {
    if let Some(header) = headers.get("forwarded") {
        let header = header.to_str().unwrap_or_default();
        return Either::Left(Either::Left(extract_forwarded_header(header)));
    }

    if let Some(header) = headers.get("x-forwarded-for") {
        let header = header.to_str().unwrap_or_default();
        return Either::Left(Either::Right(extract_x_forwarded_for_header(header)));
    }

    if let Some(header) = headers.get("x-real-ip") {
        let header = header.to_str().unwrap_or_default();
        return Either::Right(Either::Left(extract_real_ip_header(header)));
    }

    Either::Right(Either::Right(empty()))
}

#[allow(dead_code)]
#[doc = include_str!("../README.md")]
fn test_readme_examples() {}
