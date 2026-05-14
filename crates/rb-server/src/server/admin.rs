use super::http::*;

const ADMIN_APP_JS: &str = include_str!("admin/app.js");
const ADMIN_INDEX_HTML: &str = include_str!("admin/index.html");
const ADMIN_RENDER_HELPERS_JS: &str = include_str!("admin/render_helpers.js");
const ADMIN_STATE_JS: &str = include_str!("admin/state.js");
const ADMIN_STYLES_CSS: &str = include_str!("admin/styles.css");
const ADMIN_CACHE_CONTROL: &str = "no-store";
const ADMIN_CSP: &str = "default-src 'none'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'";

pub(crate) fn admin_index_response() -> HttpResponse {
    admin_response(
        200,
        "text/html; charset=utf-8",
        ADMIN_INDEX_HTML.as_bytes().to_vec(),
    )
    .with_header("Content-Security-Policy", ADMIN_CSP)
}

pub(crate) fn admin_asset_response(asset: &str) -> Option<HttpResponse> {
    match asset {
        "app.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_APP_JS.as_bytes().to_vec(),
        )),
        "render_helpers.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_RENDER_HELPERS_JS.as_bytes().to_vec(),
        )),
        "state.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_STATE_JS.as_bytes().to_vec(),
        )),
        "styles.css" => Some(admin_response(
            200,
            "text/css; charset=utf-8",
            ADMIN_STYLES_CSS.as_bytes().to_vec(),
        )),
        _ => None,
    }
}

fn admin_response(status: u16, content_type: &'static str, body: Vec<u8>) -> HttpResponse {
    HttpResponse::bytes(status, content_type, body)
        .with_header("Cache-Control", ADMIN_CACHE_CONTROL)
        .with_header("X-Content-Type-Options", "nosniff")
}
