use super::http::*;

const ADMIN_INDEX_HTML: &str = include_str!("admin/index.html");

pub(crate) fn admin_index_response() -> HttpResponse {
    HttpResponse::bytes(
        200,
        "text/html; charset=utf-8",
        ADMIN_INDEX_HTML.as_bytes().to_vec(),
    )
    .with_header("Cache-Control", "no-store")
    .with_header(
        "Content-Security-Policy",
        "default-src 'none'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
    )
}
