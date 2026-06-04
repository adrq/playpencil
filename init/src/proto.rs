use serde::{Deserialize, Serialize};

/// How the guest interprets an exec command vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecMode {
    /// `cmd` is an argv vector run via `execvp(cmd[0], cmd)`.
    #[default]
    Argv,
    /// `cmd[0]` is a shell line run via the resolved shell (`-c`).
    Shell,
}

/// Messages sent from the host to the guest (incoming).
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostMessage {
    Exec {
        id: String,
        cmd: Vec<String>,
        #[serde(default)]
        env: Vec<String>,
        #[serde(default)]
        workdir: Option<String>,
        #[serde(default)]
        uid: Option<u32>,
        #[serde(default)]
        gid: Option<u32>,
        #[serde(default)]
        mode: ExecMode,
    },
    Stdin {
        id: String,
        data: String,
    },
    Signal {
        id: String,
        signal: i32,
    },
    #[allow(dead_code)]
    Resize {
        id: String,
        cols: u32,
        rows: u32,
    },
    /// Output flow-control: stop reading this child's stdout/stderr.
    Pause {
        id: String,
    },
    /// Output flow-control: resume reading this child's stdout/stderr.
    Resume {
        id: String,
    },
}

/// Messages sent from the guest to the host (outgoing).
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GuestMessage {
    Stdout {
        id: String,
        data: String,
    },
    Stderr {
        id: String,
        data: String,
    },
    Exit {
        id: String,
        code: i32,
    },
    /// The command never started as intended (distinct from a numeric exit).
    StartError {
        id: String,
        message: String,
    },
    /// Input flow-control: grant the host `bytes` more stdin send-credit.
    StdinCredit {
        id: String,
        bytes: usize,
    },
    /// The child closed its stdin while still running: the host must stop
    /// sending stdin for this id (its relay terminates so writes fail loudly
    /// rather than waiting on credit that will never be granted).
    StdinClosed {
        id: String,
    },
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

/// Decode standard base64. Returns None on invalid input.
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let without_padding = input.trim_end_matches('=');
    let pad = (4 - without_padding.len() % 4) % 4;
    if pad > 2 {
        return None;
    }

    fn char_to_val(c: char) -> Option<u32> {
        match c {
            'A'..='Z' => Some(c as u32 - 'A' as u32),
            'a'..='z' => Some(c as u32 - 'a' as u32 + 26),
            '0'..='9' => Some(c as u32 - '0' as u32 + 52),
            '+' => Some(62),
            '/' => Some(63),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity((without_padding.len() * 3) / 4 + 1);
    let chars: Vec<char> = without_padding.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let v0 = char_to_val(chars[i])?;
        let v1 = if i + 1 < chars.len() {
            char_to_val(chars[i + 1])?
        } else {
            0
        };
        let v2 = if i + 2 < chars.len() {
            char_to_val(chars[i + 2])?
        } else {
            0
        };
        let v3 = if i + 3 < chars.len() {
            char_to_val(chars[i + 3])?
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
    fn test_base64_roundtrip() {
        let data = b"hello world\x00\xff\x01";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_decode_empty() {
        assert_eq!(base64_decode("").unwrap(), b"");
    }

    #[test]
    fn test_base64_decode_hello() {
        let decoded = base64_decode("SGVsbG8sIFdvcmxkIQ==").unwrap();
        assert_eq!(decoded, b"Hello, World!");
    }

    #[test]
    fn test_host_message_exec_deserialize() {
        let json =
            r#"{"type":"exec","id":"e1","cmd":["echo","hi"],"env":["FOO=1"],"workdir":"/tmp"}"#;
        let msg: HostMessage = serde_json::from_str(json).unwrap();
        match msg {
            HostMessage::Exec {
                id,
                cmd,
                env,
                workdir,
                ..
            } => {
                assert_eq!(id, "e1");
                assert_eq!(cmd, vec!["echo", "hi"]);
                assert_eq!(env, vec!["FOO=1"]);
                assert_eq!(workdir.as_deref(), Some("/tmp"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_host_message_exec_defaults() {
        let json = r#"{"type":"exec","id":"e2","cmd":["ls"]}"#;
        let msg: HostMessage = serde_json::from_str(json).unwrap();
        match msg {
            HostMessage::Exec {
                env,
                workdir,
                uid,
                gid,
                mode,
                ..
            } => {
                assert!(env.is_empty());
                assert_eq!(workdir, None);
                // Additive fields default so old hosts stay wire-compatible.
                assert_eq!(uid, None);
                assert_eq!(gid, None);
                assert_eq!(mode, ExecMode::Argv);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_host_message_exec_shell_mode_and_creds() {
        let json = r#"{"type":"exec","id":"e3","cmd":["echo hi | wc -c"],"mode":"shell","uid":1000,"gid":2000}"#;
        let msg: HostMessage = serde_json::from_str(json).unwrap();
        match msg {
            HostMessage::Exec { mode, uid, gid, .. } => {
                assert_eq!(mode, ExecMode::Shell);
                assert_eq!(uid, Some(1000));
                assert_eq!(gid, Some(2000));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_pause_resume_deserialize() {
        let p: HostMessage = serde_json::from_str(r#"{"type":"pause","id":"e1"}"#).unwrap();
        assert!(matches!(p, HostMessage::Pause { id } if id == "e1"));
        let r: HostMessage = serde_json::from_str(r#"{"type":"resume","id":"e1"}"#).unwrap();
        assert!(matches!(r, HostMessage::Resume { id } if id == "e1"));
    }

    #[test]
    fn test_guest_start_error_and_credit_serialize() {
        let se = GuestMessage::StartError {
            id: "e1".into(),
            message: "no shell available".into(),
        };
        let json = serde_json::to_string(&se).unwrap();
        assert!(json.contains("\"type\":\"start_error\""));
        assert!(json.contains("\"message\":\"no shell available\""));

        let cr = GuestMessage::StdinCredit {
            id: "e1".into(),
            bytes: 4096,
        };
        let json = serde_json::to_string(&cr).unwrap();
        assert!(json.contains("\"type\":\"stdin_credit\""));
        assert!(json.contains("\"bytes\":4096"));
    }

    #[test]
    fn test_host_message_stdin_deserialize() {
        let json = r#"{"type":"stdin","id":"e1","data":"aGVsbG8="}"#;
        let msg: HostMessage = serde_json::from_str(json).unwrap();
        match msg {
            HostMessage::Stdin { id, data } => {
                assert_eq!(id, "e1");
                assert_eq!(data, "aGVsbG8=");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_guest_message_stdout_serialize() {
        let msg = GuestMessage::Stdout {
            id: "e1".into(),
            data: base64_encode(b"out"),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"stdout\""));
        assert!(json.contains("\"id\":\"e1\""));
        assert!(json.contains("\"b3V0\""));
    }

    #[test]
    fn test_guest_message_exit_serialize() {
        let msg = GuestMessage::Exit {
            id: "e1".into(),
            code: 42,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"exit\""));
        assert!(json.contains("\"code\":42"));
    }
}
