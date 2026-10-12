use serde::Serialize;
use utoipa::openapi::RefOr;
use utoipa::openapi::schema::{AnyOfBuilder, ObjectBuilder, Schema, Type};
use utoipa::{PartialSchema, ToSchema};

use super::sandbox::SandboxDocument;

/// The document after a change.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ChangedEvent {
    #[schema(minimum = 0, maximum = 9223372036854775807_i64)]
    pub(crate) seq: u64,
    #[schema(format = DateTime)]
    pub(crate) at: String,
    pub(crate) document: SandboxDocument,
}

/// Typed by `code`.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct NoticeEvent {
    #[schema(minimum = 0, maximum = 9223372036854775807_i64)]
    pub(crate) seq: u64,
    #[schema(format = DateTime)]
    pub(crate) at: String,
    #[serde(flatten)]
    pub(crate) notice: Notice,
}

/// A notice, typed by `code`.
#[expect(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "code", rename_all = "snake_case")]
pub(crate) enum Notice {
    /// A connection or DNS query was refused.
    Deny {
        #[schema(nullable = false)]
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        details: DenyDetails,
    },
    /// Addresses authorized for a name.
    PinRegistered {
        #[schema(nullable = false)]
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        details: PinRegisteredDetails,
    },
    /// Addresses no longer authorized.
    PinExpired {
        #[schema(nullable = false)]
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        details: PinExpiredDetails,
    },
    /// Host addresses changed.
    HostAddressesChanged {
        #[schema(nullable = false)]
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        details: HostAddressesChangedDetails,
    },
    /// Ends the baseline, which follows any replay; later events are live.
    Resync {
        #[schema(nullable = false)]
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// A stop or destroy killed before the guest flushed; recent writes may be lost.
    FlushIncomplete {
        #[schema(nullable = false)]
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        details: FlushIncompleteDetails,
    },
    /// Events were lost; always delivered.
    Gap {
        #[schema(nullable = false)]
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        details: GapDetails,
    },
}

/// At least one of `name` and `ip`.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DenyDetails {
    #[serde(flatten)]
    pub(crate) destination: Destination,
    #[schema(minimum = 0, maximum = 65535)]
    pub(crate) port: u16,
    /// `tcp` or `udp`.
    pub(crate) protocol: String,
    /// `unmatched`, `host_local`, `resolution_validation` or `mode`.
    pub(crate) cause: String,
    /// Name whose expired pin caused the denial.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) expired_pin: Option<String>,
}

/// The destination of a refused connection or query: a name, an address, or
/// both. At least one of `name` and `ip` is present.
#[cfg_attr(not(test), expect(dead_code))]
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum Destination {
    NameAndIp { name: String, ip: String },
    Name { name: String },
    Ip { ip: String },
}

impl PartialSchema for Destination {
    fn schema() -> RefOr<Schema> {
        let branch = |required: &str| {
            ObjectBuilder::new()
                .schema_type(Type::Object)
                .property("name", ObjectBuilder::new().schema_type(Type::String))
                .property("ip", ObjectBuilder::new().schema_type(Type::String))
                .required(required)
        };
        AnyOfBuilder::new()
            .description(Some(
                "The destination of a refused connection or query: a name, an \
                 address, or both. At least one of `name` and `ip` is present.",
            ))
            .item(branch("name"))
            .item(branch("ip"))
            .into()
    }
}

impl ToSchema for Destination {}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct PinRegisteredDetails {
    pub(crate) name: String,
    pub(crate) addresses: Vec<String>,
    /// `N`, `lo-hi` or `*`.
    pub(crate) ports: Vec<String>,
    #[schema(format = DateTime)]
    pub(crate) expires_at: String,
    /// `true` in the baseline.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) baseline: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct PinExpiredDetails {
    pub(crate) name: String,
    pub(crate) addresses: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct HostAddressesChangedDetails {
    pub(crate) addresses: Vec<String>,
    /// `true` in the baseline.
    #[schema(nullable = false)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) baseline: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct FlushIncompleteDetails {
    /// `stop` or `destroy`.
    pub(crate) phase: String,
    #[schema(minimum = 0, maximum = 9223372036854775807_i64)]
    pub(crate) waited_ms: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct GapDetails {
    /// Resumed-from cursor (excluded).
    pub(crate) from: String,
    /// Cut cursor (included); cursors aren't comparable.
    pub(crate) to: String,
}
