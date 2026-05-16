use super::http::*;

const ADMIN_APP_JS: &str = include_str!("admin/app.js");
const ADMIN_COLLECTIONS_AUTH_JS: &str = include_str!("admin/collections/auth.js");
const ADMIN_COLLECTIONS_FIELD_OPTIONS_JS: &str = include_str!("admin/collections/field_options.js");
const ADMIN_COLLECTIONS_FIELDS_JS: &str = include_str!("admin/collections/fields.js");
const ADMIN_COLLECTIONS_IMPORT_EXPORT_JS: &str = include_str!("admin/collections/import_export.js");
const ADMIN_COLLECTIONS_INDEXES_JS: &str = include_str!("admin/collections/indexes.js");
const ADMIN_COLLECTIONS_META_JS: &str = include_str!("admin/collections/meta.js");
const ADMIN_COLLECTIONS_RULES_JS: &str = include_str!("admin/collections/rules.js");
const ADMIN_COLLECTIONS_UI_JS: &str = include_str!("admin/collections_ui.js");
const ADMIN_DATA_HELPERS_JS: &str = include_str!("admin/data_helpers.js");
const ADMIN_INDEX_HTML: &str = include_str!("admin/index.html");
const ADMIN_RECORDS_BROWSER_JS: &str = include_str!("admin/records/browser.js");
const ADMIN_RECORDS_EDITOR_JS: &str = include_str!("admin/records/editor.js");
const ADMIN_RECORDS_FILES_JS: &str = include_str!("admin/records/files.js");
const ADMIN_RECORDS_RELATIONS_JS: &str = include_str!("admin/records/relations.js");
const ADMIN_RECORDS_VALIDATION_JS: &str = include_str!("admin/records/validation.js");
const ADMIN_RECORDS_UI_JS: &str = include_str!("admin/records_ui.js");
const ADMIN_RENDER_HELPERS_JS: &str = include_str!("admin/render_helpers.js");
const ADMIN_SETTINGS_UI_JS: &str = include_str!("admin/settings_ui.js");
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
        "collections_ui.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_COLLECTIONS_UI_JS.as_bytes().to_vec(),
        )),
        "collections/auth.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_COLLECTIONS_AUTH_JS.as_bytes().to_vec(),
        )),
        "collections/field_options.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_COLLECTIONS_FIELD_OPTIONS_JS.as_bytes().to_vec(),
        )),
        "collections/fields.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_COLLECTIONS_FIELDS_JS.as_bytes().to_vec(),
        )),
        "collections/import_export.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_COLLECTIONS_IMPORT_EXPORT_JS.as_bytes().to_vec(),
        )),
        "collections/indexes.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_COLLECTIONS_INDEXES_JS.as_bytes().to_vec(),
        )),
        "collections/meta.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_COLLECTIONS_META_JS.as_bytes().to_vec(),
        )),
        "collections/rules.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_COLLECTIONS_RULES_JS.as_bytes().to_vec(),
        )),
        "data_helpers.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_DATA_HELPERS_JS.as_bytes().to_vec(),
        )),
        "records_ui.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_RECORDS_UI_JS.as_bytes().to_vec(),
        )),
        "records/browser.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_RECORDS_BROWSER_JS.as_bytes().to_vec(),
        )),
        "records/editor.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_RECORDS_EDITOR_JS.as_bytes().to_vec(),
        )),
        "records/files.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_RECORDS_FILES_JS.as_bytes().to_vec(),
        )),
        "records/relations.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_RECORDS_RELATIONS_JS.as_bytes().to_vec(),
        )),
        "records/validation.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_RECORDS_VALIDATION_JS.as_bytes().to_vec(),
        )),
        "render_helpers.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_RENDER_HELPERS_JS.as_bytes().to_vec(),
        )),
        "settings_ui.js" => Some(admin_response(
            200,
            "text/javascript; charset=utf-8",
            ADMIN_SETTINGS_UI_JS.as_bytes().to_vec(),
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
