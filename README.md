# real-ip

Get the "real-ip" of an incoming request using the "forwarded", "x-forwarded-for" or "x-real-ip" headers set by reverse proxies.

See the [crate documentation](https://docs.rs/real-ip) for more details and examples.

## Example

```rust
use http::Request;
use std::net::IpAddr;
use ipnetwork::IpNetwork;
use real_ip::real_ip;

// in a real program this info would of course come from the http server
let incoming_ip = IpAddr::from([10, 0, 0, 1]);
let request = Request::builder().header("x-forwarded-for", "192.0.2.1").body(()).unwrap();

// the reverse-proxies in our network that we trust
let trusted_proxies = [
    IpAddr::from([10, 0, 0, 1]).into(),
];
let client_ip = real_ip(request.headers(), incoming_ip, &trusted_proxies);
assert_eq!(Some(IpAddr::from([192, 0, 2, 1])), client_ip);
```
