use super::http::*;

const ADMIN_INDEX_HTML: &str = include_str!("admin/index.html");

pub(crate) fn admin_index_response() -> HttpResponse {
    HttpResponse::bytes(
        200,
        "text/html; charset=utf-8",
        ADMIN_INDEX_HTML.as_bytes().to_vec(),
    )
    .with_header("Cache-Control", "no-store")
}
