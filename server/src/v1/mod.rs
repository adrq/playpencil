//! The `/v1` HTTP API contract: wire types and operation declarations from
//! which the OpenAPI document is generated.

mod ops;
mod types;

use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Playpencil API",
        version = "v1",
        description = include_str!("description.md"),
        license(name = "AGPL-3.0-or-later", identifier = "AGPL-3.0-or-later"),
    ),
    tags(
        (name = "sandboxes"),
        (name = "events"),
        (name = "processes"),
        (name = "streams"),
        (name = "system"),
    ),
    paths(
        ops::sandboxes::create_sandbox,
        ops::sandboxes::list_sandboxes,
        ops::sandboxes::get_sandbox,
        ops::sandboxes::update_sandbox,
        ops::events::stream_sandbox_events,
        ops::streams::open_stream,
        ops::processes::spawn_process,
        ops::processes::list_processes,
        ops::processes::get_process,
        ops::processes::interrupt_process,
        ops::system::get_capabilities,
        ops::system::get_health,
    ),
    components(schemas(
        types::sandbox::CreateSandboxRequest,
        types::sandbox::PatchSandboxRequest,
        types::sandbox::SandboxDocument,
        types::sandbox::SandboxList,
        types::event::ChangedEvent,
        types::event::NoticeEvent,
        types::process::ProcessRecord,
        types::process::ProcessList,
        types::command::CommandSpecWrite,
        types::capabilities::CapabilitiesResponse,
        types::problem::Problem,
        types::problem::NotFoundProblem,
        types::problem::InvalidInputProblem,
        types::problem::CreateConflictProblem,
        types::problem::PatchConflictProblem,
        types::problem::ProcessConflictProblem,
        types::problem::InternalProblem,
    )),
)]
struct ApiDoc;

/// The `/v1` document as derived from the wire types and operation
/// declarations, before finalization.
pub fn derived_openapi() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}

/// Finalizes an assembled `/v1` document's components. Apply it once to the
/// complete document, after every operation and schema has been collected.
/// Applying it again changes nothing.
pub fn finalize(api: &mut utoipa::openapi::OpenApi) -> Result<(), String> {
    types::open_union::finalize(api)
}

/// The `/v1` OpenAPI document.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut api = derived_openapi();
    finalize(&mut api).expect("the /v1 document finalizes");
    api
}

/// The `/v1` OpenAPI document as pretty-printed JSON with a trailing newline.
pub fn openapi_json() -> String {
    let mut json = openapi()
        .to_pretty_json()
        .expect("OpenAPI document serializes to JSON");
    json.push('\n');
    json
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_json(api: &utoipa::openapi::OpenApi) -> String {
        let mut json = api.to_pretty_json().unwrap();
        json.push('\n');
        json
    }

    #[test]
    fn finalize_is_idempotent() {
        let once = openapi();
        let mut twice = once.clone();
        finalize(&mut twice).unwrap();
        assert_eq!(to_json(&twice), to_json(&once));
    }

    #[test]
    fn finalize_restores_components_overwritten_by_derived_ones() {
        let expected = openapi_json();
        let derived = derived_openapi().components.unwrap().schemas;

        let mut all = openapi();
        all.components
            .as_mut()
            .unwrap()
            .schemas
            .extend(derived.clone());
        finalize(&mut all).unwrap();
        assert_eq!(to_json(&all), expected);

        for (name, schema) in derived {
            let mut one = openapi();
            one.components
                .as_mut()
                .unwrap()
                .schemas
                .insert(name.clone(), schema);
            finalize(&mut one).unwrap();
            assert_eq!(to_json(&one), expected, "after overwriting {name}");
        }
    }
}
