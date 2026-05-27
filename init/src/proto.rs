use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct ExecRequest {
    pub cmd: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub workdir: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExecResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let chunks = data.chunks(3);
    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(BASE64_ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(BASE64_ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(BASE64_ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode_empty() {
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn test_base64_encode_hello() {
        assert_eq!(base64_encode(b"Hello, World!"), "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn test_base64_encode_padding() {
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
        assert_eq!(base64_encode(b"abc"), "YWJj");
    }

    #[test]
    fn test_exec_request_deserialize() {
        let json = r#"{"cmd":["echo","hello"],"env":["FOO=bar"],"workdir":"/tmp"}"#;
        let req: ExecRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.cmd, vec!["echo", "hello"]);
        assert_eq!(req.env, vec!["FOO=bar"]);
        assert_eq!(req.workdir.as_deref(), Some("/tmp"));
    }

    #[test]
    fn test_exec_request_defaults() {
        let json = r#"{"cmd":["ls"]}"#;
        let req: ExecRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.cmd, vec!["ls"]);
        assert!(req.env.is_empty());
        assert_eq!(req.workdir, None);
    }

    #[test]
    fn test_exec_response_serialize() {
        let resp = ExecResponse {
            exit_code: 0,
            stdout: base64_encode(b"out"),
            stderr: base64_encode(b""),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"exit_code\":0"));
        assert!(json.contains("\"stdout\":\"b3V0\""));
    }
}
