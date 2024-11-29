use comma_separated::CommaSeparatedIterator;
use rfc7239::{parse, Forwarded, NodeIdentifier, NodeName};
use std::borrow::Cow;
use std::iter::IntoIterator;
use std::net::IpAddr;
use std::str::FromStr;

/// Get the list of ip addresses from an `forwarded` header
///
/// # Example
///
/// ```rust
/// # use std::net::IpAddr;
/// # use real_ip::headers::*;
/// assert_eq!(
///    vec![IpAddr::from([10, 10, 10, 10]), IpAddr::from([10, 10, 10, 20])],
///    extract_forwarded_header("for=10.10.10.10, for=10.10.10.20;proto=https").collect::<Vec<_>>()
/// );
/// ```
///
/// Note: if you need the other data provided by the `forwarded` header, have a look at the [`rfc7239`](https://docs.rs/rfc7239) crate.
pub fn extract_forwarded_header(
    header_value: &str,
) -> impl DoubleEndedIterator<Item = IpAddr> + '_ {
    parse(header_value).filter_map(|forward| match forward {
        Ok(Forwarded {
            forwarded_for:
                Some(NodeIdentifier {
                    name: NodeName::Ip(ip),
                    ..
                }),
            ..
        }) => Some(ip),
        _ => None,
    })
}

/// Get the list of ip addresses from an `x-forwarded-for` header
///
/// # Example
///
/// ```rust
/// # use std::net::IpAddr;
/// # use real_ip::headers::*;
/// assert_eq!(
///    vec![IpAddr::from([10, 10, 10, 10]), IpAddr::from([10, 10, 10, 20])],
///    extract_x_forwarded_for_header("10.10.10.10,10.10.10.20").collect::<Vec<_>>()
/// );
/// ```
pub fn extract_x_forwarded_for_header(
    header_value: &str,
) -> impl DoubleEndedIterator<Item = IpAddr> + '_ {
    CommaSeparatedIterator::new(header_value)
        .map(str::trim)
        .flat_map(|x| IpAddr::from_str(maybe_bracketed(&maybe_quoted(x))))
}

/// Get the list of ip addresses from an `x-real-ip` header
///
/// # Example
///
/// ```rust
/// # use std::net::IpAddr;
/// # use real_ip::headers::*;
/// assert_eq!(
///    vec![IpAddr::from([10, 10, 10, 10])],
///    extract_x_forwarded_for_header("10.10.10.10").collect::<Vec<_>>()
/// );
/// ```
pub fn extract_real_ip_header(header_value: &str) -> impl DoubleEndedIterator<Item = IpAddr> + '_ {
    IpAddr::from_str(maybe_bracketed(&maybe_quoted(header_value))).into_iter()
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
