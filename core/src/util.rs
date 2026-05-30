const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((triple >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(triple & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

pub(crate) fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let without_pad = input.trim_end_matches('=');
    let pad = (4 - without_pad.len() % 4) % 4;
    if pad > 2 {
        return None;
    }
    fn val(c: char) -> Option<u32> {
        match c {
            'A'..='Z' => Some(c as u32 - 'A' as u32),
            'a'..='z' => Some(c as u32 - 'a' as u32 + 26),
            '0'..='9' => Some(c as u32 - '0' as u32 + 52),
            '+' => Some(62),
            '/' => Some(63),
            _ => None,
        }
    }
    let chars: Vec<char> = without_pad.chars().collect();
    let mut out = Vec::with_capacity((chars.len() * 3) / 4 + 1);
    let mut i = 0;
    while i < chars.len() {
        let v0 = val(chars[i])?;
        let v1 = if i + 1 < chars.len() {
            val(chars[i + 1])?
        } else {
            0
        };
        let v2 = if i + 2 < chars.len() {
            val(chars[i + 2])?
        } else {
            0
        };
        let v3 = if i + 3 < chars.len() {
            val(chars[i + 3])?
        } else {
            0
        };
        let triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
        out.push(((triple >> 16) & 0xFF) as u8);
        if i + 2 < chars.len() {
            out.push(((triple >> 8) & 0xFF) as u8);
        }
        if i + 3 < chars.len() {
            out.push((triple & 0xFF) as u8);
        }
        i += 4;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let data = b"hello\x00\xff\x7f";
        assert_eq!(base64_decode(&base64_encode(data)).unwrap(), data);
    }

    #[test]
    fn test_empty() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_decode("").unwrap(), b"");
    }

    #[test]
    fn test_encode_known() {
        assert_eq!(base64_encode(b"Hello, World!"), "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn test_decode_known() {
        assert_eq!(
            base64_decode("SGVsbG8sIFdvcmxkIQ==").unwrap(),
            b"Hello, World!"
        );
    }

    #[test]
    fn test_padding_one_byte() {
        assert_eq!(base64_encode(b"A"), "QQ==");
        assert_eq!(base64_decode("QQ==").unwrap(), b"A");
    }

    #[test]
    fn test_padding_two_bytes() {
        assert_eq!(base64_encode(b"AB"), "QUI=");
        assert_eq!(base64_decode("QUI=").unwrap(), b"AB");
    }

    #[test]
    fn test_no_padding_three_bytes() {
        assert_eq!(base64_encode(b"ABC"), "QUJD");
        assert_eq!(base64_decode("QUJD").unwrap(), b"ABC");
    }

    #[test]
    fn test_decode_invalid_char() {
        assert!(base64_decode("!!!!").is_none());
    }

    #[test]
    fn test_decode_without_padding() {
        // The decoder also accepts input with the trailing '=' padding omitted.
        assert_eq!(base64_decode("QQ").unwrap(), b"A");
        assert_eq!(base64_decode("QUI").unwrap(), b"AB");
    }
}
