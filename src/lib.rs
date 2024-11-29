//! Get the "real-ip" of an incoming request.
//!
//! This uses the "forwarded", "x-forwarded-for" or "x-real-ip" headers set by reverse proxies.
//!
//! ## Trusted proxies
//!
//! To stop clients from being able to spoof the remote ip, you are required to configure the trusted proxies
//! which are allowed to set the forwarded headers.
//!
//! Trusted proxies are configured as a list of [`IpNetwork`]s, which can be a single ip or an ip range.
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
//! # use ipnetwork::IpNetwork;
//! # use real_ip::real_ip;
//! #
//! // in a real program this info would of course come from the http server
//! let incoming_ip = IpAddr::from([10, 0, 0, 1]);
//! let request = Request::builder().header("x-forwarded-for", "192.0.2.1, 10.10.10.10").body(()).unwrap();
//!
//! // the reverse-proxies in our network that we trust
//! let trusted_proxies = [
//!     IpAddr::from([10, 0, 0, 1]).into(),
//!     IpNetwork::new(IpAddr::from([10, 10, 10, 0]), 24).unwrap(), // 10.10.10.0/24
//! ];
//! let client_ip = real_ip(&request, incoming_ip, &trusted_proxies);
//! assert_eq!(Some(IpAddr::from([192, 0, 2, 1])), client_ip);
//! ```
//!
//! A request originating from 192.0.2.1, being proxied through 203.0.113.10 and 10.0.0.1 before reaching our program.
//! But 203.0.113.10 is not a trusted proxy, so we don't accept anything it added to the forwarded headers
//!
//! ```
//! # use http::Request;
//! # use std::net::IpAddr;
//! # use ipnetwork::IpNetwork;
//! # use real_ip::real_ip;
//! #
//! let incoming_ip = IpAddr::from([10, 0, 0, 1]);
//! let request = Request::builder().header("forwarded", "for=192.0.2.1, for=203.0.113.10;proto=https").body(()).unwrap();
//!
//! let trusted_proxies = [
//!     IpAddr::from([10, 0, 0, 1]).into(),
//!     IpNetwork::new(IpAddr::from([10, 10, 10, 0]), 24).unwrap(),
//! ];
//! let client_ip = real_ip(&request, incoming_ip, &trusted_proxies);
//! assert_eq!(Some(IpAddr::from([203, 0, 113, 10])), client_ip);
//! ```

use comma_separated::CommaSeparatedIterator;
use http::Request;
use ipnetwork::IpNetwork;
use itertools::Either;
use rfc7239::{parse, Forwarded, NodeIdentifier, NodeName};
use std::borrow::Cow;
use std::iter::{empty, once, IntoIterator};
use std::net::IpAddr;
use std::str::FromStr;

/// Get the "real-ip" of an incoming request.
///
/// See the [top level documentation](crate) for more usage details.
pub fn real_ip<B>(
    request: &Request<B>,
    remote: IpAddr,
    trusted_proxies: &[IpNetwork],
) -> Option<IpAddr> {
    let mut hops = get_forwarded_for(request).chain(once(remote));
    let first = hops.next();
    let hops = first.iter().copied().chain(hops);

    'outer: for hop in hops.rev() {
        for proxy in trusted_proxies {
            if proxy.contains(hop) {
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
pub fn get_forwarded_for<B>(request: &Request<B>) -> impl DoubleEndedIterator<Item = IpAddr> + '_ {
    let headers = request.headers();
    if let Some(header) = headers.get("forwarded") {
        let header = header.to_str().unwrap_or_default();
        let hops = parse(header).filter_map(|forward| match forward {
            Ok(Forwarded {
                forwarded_for:
                    Some(NodeIdentifier {
                        name: NodeName::Ip(ip),
                        ..
                    }),
                ..
            }) => Some(ip),
            _ => None,
        });
        return Either::Left(Either::Left(hops));
    }

    if let Some(header) = headers.get("x-forwarded-for") {
        let header = header.to_str().unwrap_or_default();
        let hops = CommaSeparatedIterator::new(header)
            .map(str::trim)
            .flat_map(|x| IpAddr::from_str(maybe_bracketed(&maybe_quoted(x))));
        return Either::Left(Either::Right(hops));
    }

    if let Some(header) = headers.get("x-real-ip") {
        let header = header.to_str().unwrap_or_default();
        return Either::Right(Either::Left(
            IpAddr::from_str(maybe_bracketed(&maybe_quoted(header))).into_iter(),
        ));
    }

    Either::Right(Either::Right(empty()))
}

enum EscapeState {
    Normal,
    Escaped,
}

fn maybe_quoted(x: &str) -> Cow<str> {
    let mut i = x.chars();
    if i.next() == Some('"') {
        let mut s = String::with_capacity(x.len());
        let mut state = EscapeState::Normal;
        for c in i {
            state = match state {
                EscapeState::Normal => match c {
                    '"' => break,
                    '\\' => EscapeState::Escaped,
                    _ => {
                        s.push(c);
                        EscapeState::Normal
                    }
                },
                EscapeState::Escaped => {
                    s.push(c);
                    EscapeState::Normal
                }
            };
        }
        s.into()
    } else {
        x.into()
    }
}

fn maybe_bracketed(x: &str) -> &str {
    if x.as_bytes().first() == Some(&b'[') && x.as_bytes().last() == Some(&b']') {
        &x[1..x.len() - 1]
    } else {
        x
    }
}

#[allow(dead_code)]
#[doc = include_str!("../README.md")]
fn test_readme_examples() {}
