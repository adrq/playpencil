/// Open the streaming link.
///
/// WebSocket upgrade to the streaming-link protocol (open processes, attach, control); its frames aren't described here. A stream whose owning link drops is held for the reap tolerance, then interrupted.
#[expect(dead_code)]
#[utoipa::path(
    get,
    path = "/v1/streams",
    operation_id = "open_stream",
    tag = "streams",
    responses(
        (status = 101, description = "Switching protocols.",
            headers(
                ("Upgrade" = String, description = "`websocket`"),
                ("Connection" = String, description = "`Upgrade`"),
            ),
        ),
    ),
)]
pub(crate) async fn open_stream() {}
