//! Prints the `/v1` OpenAPI document to stdout.

fn main() {
    print!("{}", playpencil_server::openapi_json());
}
