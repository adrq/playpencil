use crate::v1::types::problem::{NotFoundProblem, Problem};
use crate::v1::types::query::EventsQuery;

/// Stream a sandbox's events.
///
/// Server-sent events: `event` is `changed` or `notice`, `id` the cursor, `data` a `ChangedEvent` or `NoticeEvent`. Resume with the cursor as `since` or `Last-Event-ID` (preferred).
///
/// On connect: (1) with a cursor, the events after it are replayed, or a `gap` notice if they aren't retained; (2) the baseline at one cut (`changed`, `pin_registered`, `host_addresses_changed`; flagged `baseline: true`, with the cut `seq` and cursor); (3) `resync`; (4) live events, including changes made during the baseline. A policy change's `changed` event separates denials under the old and new policy. The buffer is bounded.
#[expect(dead_code)]
#[utoipa::path(
    get,
    path = "/v1/sandboxes/{id}/events",
    operation_id = "stream_sandbox_events",
    tag = "events",
    params(
        ("id" = String, Path, description = "Sandbox id."),
        EventsQuery,
        ("Last-Event-ID" = Option<String>, Header, nullable = false, description = "Takes precedence over `since`."),
    ),
    responses(
        (status = 200, description = "Event stream.", body = String, content_type = "text/event-stream"),
        (status = 400, description = "Unparseable.", body = Problem, content_type = "application/problem+json"),
        (status = 401, description = "Reserved."),
        (status = 403, description = "Reserved."),
        (status = 404, description = "Not found.", body = NotFoundProblem, content_type = "application/problem+json"),
    ),
)]
pub(crate) async fn stream_sandbox_events() {}
