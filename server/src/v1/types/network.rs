use serde::de::IgnoredAny;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utoipa::openapi::schema::{ArrayBuilder, Object, Type};
use utoipa::openapi::{RefOr, Schema};
use utoipa::{PartialSchema, ToSchema};

use super::serde_util::non_null;

/// `none`: nothing reachable. `allowlist`: only the entries. `all`: all egress; entries only grant host-local access.
///
/// Host-local addresses (loopback, link-local, the host's own, the daemon's) are reachable only via `host.internal` (an exact entry, never matched by a wildcard) or a covering address or CIDR, which keeps granting even if the host later acquires the address; guest loopback never reaches the host. Names match exactly, `*.name` proper subdomains only, addresses and CIDRs by prefix; TCP and UDP only. Only permitted names resolve (others get NXDOMAIN and a `deny` notice), to public addresses only (under `all`, also non-host special-use ones) unless a literal covers them; resolved addresses are pinned until TTL expiry or re-resolution.
///
/// Entries are `(name|*.name|ip|cidr):(N|lo-hi|*)` in canonical form, else `422`. Names: lowercase A-labels of `a-z0-9-`, no edge hyphens, `--` only in a leading `xn--`, labels ≤ 63 and names ≤ 253 octets (`*.` included), no trailing dot, last label not all digits. IPv6 bracketed in RFC 5952 form, no zone or IPv4-mapped; IPv4 without leading zeros; split at the last `:`. CIDRs without host bits; full-length prefixes written as the address. Ports 1–65535 without leading zeros, `lo < hi`; `N-N` written `N`, `1-65535` written `*`.
///
/// Writes apply atomically: on return, new connections and DNS use the new policy and flows it no longer authorizes are closed; a rejected write changes nothing. Pin expiry and host address changes re-check flows likewise. Processes that escaped a `BestEffort` teardown keep their old policy.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(remote = "Self")]
#[serde(tag = "mode", rename_all = "snake_case")]
pub(crate) enum NetworkWrite {
    None {
        #[schema(nullable = false)]
        #[serde(
            default,
            deserialize_with = "non_null",
            skip_serializing_if = "Option::is_none"
        )]
        entries: Option<EmptyEntries>,
    },
    Allowlist {
        entries: Vec<String>,
    },
    All {
        entries: Vec<String>,
    },
}

/// As written; `mode` may take other values.
#[expect(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub(crate) enum NetworkRead {
    None {
        /// Only if written.
        #[schema(nullable = false)]
        #[serde(skip_serializing_if = "Option::is_none")]
        entries: Option<EmptyEntries>,
    },
    Allowlist {
        entries: Vec<String>,
    },
    All {
        entries: Vec<String>,
    },
}

/// An entry list that must be empty.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct EmptyEntries;

impl<'de> Deserialize<'de> for EmptyEntries {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let items = Vec::<IgnoredAny>::deserialize(deserializer)?;
        if items.is_empty() {
            Ok(EmptyEntries)
        } else {
            Err(serde::de::Error::invalid_length(
                items.len(),
                &"no entries for mode `none`",
            ))
        }
    }
}

impl Serialize for EmptyEntries {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(std::iter::empty::<String>())
    }
}

impl PartialSchema for EmptyEntries {
    fn schema() -> RefOr<Schema> {
        ArrayBuilder::new()
            .items(Object::with_type(Type::String))
            .max_items(Some(0))
            .into()
    }
}

impl ToSchema for EmptyEntries {}

super::serde_util::object_only!(NetworkWrite);
