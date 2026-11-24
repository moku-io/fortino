//! `application/x-www-form-urlencoded` helpers.

/// Percent-encodes everything except RFC 3986 unreserved characters.
// Every other byte is sent as uppercase `%XX`, the form encoding the gateway expects.
pub(crate) fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(hex(b >> 4));
            out.push(hex(b & 0xf));
        }
    }
    out
}

fn hex(n: u8) -> char {
    char::from(if n < 10 { b'0' + n } else { b'A' + n - 10 })
}

/// Percent-decodes a value (`+` is a space). Invalid escapes are kept literally.
pub(crate) fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match std::str::from_utf8(&b[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    Some(v) => {
                        out.push(v);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let s = "a b&c=d/é%";
        assert_eq!(encode(s), "a%20b%26c%3Dd%2F%C3%A9%25");
        assert_eq!(decode(&encode(s)), s);
        assert_eq!(decode("%2Fremote%2Findex"), "/remote/index");
        assert_eq!(decode("100%"), "100%");
        assert_eq!(decode("%zz"), "%zz");
    }

    #[test]
    fn keeps_only_forticlient_set() {
        assert_eq!(encode("Az09-._~"), "Az09-._~");
        assert_eq!(encode("!*'()+"), "%21%2A%27%28%29%2B");
    }
}
