//! `/v1` routes, registered against their operation declarations.

use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::ops;
use crate::health::HealthState;

fn register(router: OpenApiRouter<HealthState>) -> OpenApiRouter<HealthState> {
    router.routes(routes!(ops::system::get_health))
}

/// The routed `/v1` operations.
pub(crate) fn router(health: HealthState) -> axum::Router {
    let (router, _) = register(OpenApiRouter::new()).split_for_parts();
    router.with_state(health)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_routes_are_health_only_and_match_declaration() {
        let registered = register(OpenApiRouter::new()).into_openapi();
        let paths: Vec<&String> = registered.paths.paths.keys().collect();
        assert_eq!(paths, vec!["/v1/health"]);

        let item = serde_json::to_value(&registered.paths.paths["/v1/health"]).unwrap();
        let methods: Vec<&String> = item.as_object().unwrap().keys().collect();
        assert_eq!(methods, vec!["get"]);

        let derived = super::super::derived_openapi();
        assert_eq!(
            item,
            serde_json::to_value(&derived.paths.paths["/v1/health"]).unwrap()
        );
    }
}
