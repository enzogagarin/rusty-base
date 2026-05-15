use rb_filter_engine::{FilterContext, Value as FilterValue};
use rb_server::{
    CollectionConfig, CollectionField, CollectionFieldKind, HttpRequest, ListOptions,
    RealtimeConnection, RealtimeEvent, RustyBaseApp, Store,
};
use rusqlite::{params, Connection};
use serde_json::{json, Value as JsonValue};
use std::{
    env, fs,
    io::{BufRead, BufReader, Cursor, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process, thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct OAuth2FixtureProvider {
    token_url: String,
    user_info_url: String,
    handle: thread::JoinHandle<()>,
}

fn spawn_oauth2_fixture_provider() -> OAuth2FixtureProvider {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        for _ in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            handle_oauth2_fixture_request(stream);
        }
    });

    OAuth2FixtureProvider {
        token_url: format!("http://{addr}/token"),
        user_info_url: format!("http://{addr}/userinfo"),
        handle,
    }
}

fn handle_oauth2_fixture_request(mut stream: TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    reader.read_line(&mut request_line).unwrap();

    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).unwrap();
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap();
            }
        }
    }

    let mut body = vec![0; content_length];
    reader.read_exact(&mut body).unwrap();
    let body = String::from_utf8(body).unwrap();

    if request_line.starts_with("POST /token ") && body.contains("code=remote_code") {
        write_oauth2_fixture_json(
            &mut stream,
            200,
            r#"{"access_token":"remote_access","refresh_token":"remote_refresh","expires_in":3600}"#,
        );
    } else if request_line.starts_with("GET /userinfo ") {
        write_oauth2_fixture_json(
            &mut stream,
            200,
            r#"{"id":42,"email":"remote@example.com","preferred_username":"remote_user","name":"Remote User","picture":"http://127.0.0.1/avatar.png"}"#,
        );
    } else {
        write_oauth2_fixture_json(&mut stream, 404, r#"{"error":"not_found"}"#);
    }
}

fn write_oauth2_fixture_json(stream: &mut TcpStream, status: u16, body: &str) {
    let reason = if status == 200 { "OK" } else { "Not Found" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).unwrap();
}

#[test]
fn serves_embedded_admin_ui_shell() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    for path in ["/admin", "/admin/collections", "/_/"] {
        let response = app.handle(HttpRequest::new("GET", path));
        assert_eq!(response.status, 200);
        assert_eq!(response.content_type, "text/html; charset=utf-8");
        assert_eq!(
            response.headers.get("cache-control").map(String::as_str),
            Some("no-store")
        );
        assert_eq!(
            response
                .headers
                .get("x-content-type-options")
                .map(String::as_str),
            Some("nosniff")
        );
        let csp = response
            .headers
            .get("content-security-policy")
            .expect("admin shell should set a CSP header");
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("connect-src 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("script-src 'self'"));
        assert!(csp.contains("style-src 'self'"));
        assert!(!csp.contains("'unsafe-inline'"));

        let html = String::from_utf8(response.raw_body).unwrap();
        assert!(html.contains("Rusty Base Admin"));
        assert!(html.contains(r#"href="/_/admin/styles.css""#));
        assert!(html.contains(r#"src="/_/admin/app.js""#));
        assert!(html.contains(r#"data-view="records""#));
        assert!(!html.contains("<style>"));
        assert!(!html.contains("const tokenKey"));
    }

    let app_js = app.handle(HttpRequest::new("GET", "/_/admin/app.js"));
    assert_eq!(app_js.status, 200);
    assert_eq!(app_js.content_type, "text/javascript; charset=utf-8");
    assert_eq!(
        app_js.headers.get("cache-control").map(String::as_str),
        Some("no-store")
    );
    assert_eq!(
        app_js
            .headers
            .get("x-content-type-options")
            .map(String::as_str),
        Some("nosniff")
    );
    let js = String::from_utf8(app_js.raw_body).unwrap();

    let state_js = app.handle(HttpRequest::new("GET", "/_/admin/state.js"));
    assert_eq!(state_js.status, 200);
    assert_eq!(state_js.content_type, "text/javascript; charset=utf-8");
    let state_js = String::from_utf8(state_js.raw_body).unwrap();

    let collections_ui_js = app.handle(HttpRequest::new("GET", "/_/admin/collections_ui.js"));
    assert_eq!(collections_ui_js.status, 200);
    assert_eq!(
        collections_ui_js.content_type,
        "text/javascript; charset=utf-8"
    );
    let collections_ui_js = String::from_utf8(collections_ui_js.raw_body).unwrap();

    let records_ui_js = app.handle(HttpRequest::new("GET", "/_/admin/records_ui.js"));
    assert_eq!(records_ui_js.status, 200);
    assert_eq!(records_ui_js.content_type, "text/javascript; charset=utf-8");
    let records_ui_js = String::from_utf8(records_ui_js.raw_body).unwrap();

    let records_browser_js = app.handle(HttpRequest::new("GET", "/_/admin/records/browser.js"));
    assert_eq!(records_browser_js.status, 200);
    assert_eq!(
        records_browser_js.content_type,
        "text/javascript; charset=utf-8"
    );
    let records_browser_js = String::from_utf8(records_browser_js.raw_body).unwrap();

    let records_editor_js = app.handle(HttpRequest::new("GET", "/_/admin/records/editor.js"));
    assert_eq!(records_editor_js.status, 200);
    assert_eq!(
        records_editor_js.content_type,
        "text/javascript; charset=utf-8"
    );
    let records_editor_js = String::from_utf8(records_editor_js.raw_body).unwrap();

    let records_files_js = app.handle(HttpRequest::new("GET", "/_/admin/records/files.js"));
    assert_eq!(records_files_js.status, 200);
    assert_eq!(
        records_files_js.content_type,
        "text/javascript; charset=utf-8"
    );
    let records_files_js = String::from_utf8(records_files_js.raw_body).unwrap();

    let records_relations_js = app.handle(HttpRequest::new("GET", "/_/admin/records/relations.js"));
    assert_eq!(records_relations_js.status, 200);
    assert_eq!(
        records_relations_js.content_type,
        "text/javascript; charset=utf-8"
    );
    let records_relations_js = String::from_utf8(records_relations_js.raw_body).unwrap();

    let records_validation_js =
        app.handle(HttpRequest::new("GET", "/_/admin/records/validation.js"));
    assert_eq!(records_validation_js.status, 200);
    assert_eq!(
        records_validation_js.content_type,
        "text/javascript; charset=utf-8"
    );
    let records_validation_js = String::from_utf8(records_validation_js.raw_body).unwrap();

    let render_helpers_js = app.handle(HttpRequest::new("GET", "/_/admin/render_helpers.js"));
    assert_eq!(render_helpers_js.status, 200);
    assert_eq!(
        render_helpers_js.content_type,
        "text/javascript; charset=utf-8"
    );
    let render_helpers_js = String::from_utf8(render_helpers_js.raw_body).unwrap();

    let data_helpers_js = app.handle(HttpRequest::new("GET", "/_/admin/data_helpers.js"));
    assert_eq!(data_helpers_js.status, 200);
    assert_eq!(
        data_helpers_js.content_type,
        "text/javascript; charset=utf-8"
    );
    let data_helpers_js = String::from_utf8(data_helpers_js.raw_body).unwrap();

    let js_bundle = format!(
        "{js}\n{state_js}\n{collections_ui_js}\n{records_ui_js}\n{records_browser_js}\n{records_editor_js}\n{records_files_js}\n{records_relations_js}\n{records_validation_js}\n{render_helpers_js}\n{data_helpers_js}"
    );
    assert!(js_bundle.contains("/api/health"));
    assert!(js_bundle.contains("/api/collections/_superusers/auth-with-password"));
    assert!(js_bundle.contains("/api/collections?fields="));
    assert!(js_bundle.contains("/api/settings?fields="));
    assert!(js_bundle.contains("collectionRecordsPath"));
    assert!(js_bundle.contains("recordListPath"));
    assert!(js_bundle.contains("relationFieldNames"));
    assert!(js_bundle.contains("params.set(\"expand\""));
    assert!(js_bundle.contains("URLSearchParams"));
    assert!(js_bundle.contains("record-filter"));
    assert!(js_bundle.contains("record-sort"));
    assert!(js_bundle.contains("record-per-page"));
    assert!(js_bundle.contains("record-next-page"));
    assert!(js_bundle.contains("Login or initialize first"));
    assert!(js_bundle.contains("collection-json-input"));
    assert!(js_bundle.contains("Create collection"));
    assert!(js_bundle.contains("Edit ${state.collectionEditorName}"));
    assert!(js_bundle.contains("data-collection-edit"));
    assert!(js_bundle.contains("data-collection-truncate"));
    assert!(js_bundle.contains("data-collection-delete"));
    assert!(js_bundle.contains("confirmDangerousAction"));
    assert!(js_bundle.contains("window.prompt"));
    assert!(!js_bundle.contains("confirm("));
    assert!(js_bundle.contains("editableCollectionPayload"));
    assert!(js_bundle.contains("collectionPath"));
    assert!(js_bundle.contains("new-field-name"));
    assert!(js_bundle.contains("new-field-min-select"));
    assert!(js_bundle.contains("new-field-max-select"));
    assert!(js_bundle.contains("new-field-protected"));
    assert!(js_bundle.contains("collectionFieldEditIndex"));
    assert!(js_bundle.contains("data-field-edit"));
    assert!(js_bundle.contains("cancel-field-edit"));
    assert!(js_bundle.contains("syncCollectionFieldToolControls"));
    assert!(js_bundle.contains("addCollectionField"));
    assert!(js_bundle.contains("removeCollectionField"));
    assert!(js_bundle.contains("Field name is required"));
    assert!(js_bundle.contains("Relation target collection is required"));
    assert!(js_bundle.contains("Select values are required"));
    assert!(js_bundle.contains("Protected only applies to file fields"));
    assert!(js_bundle.contains("Go to Collections"));
    assert!(js_bundle.contains("record-json-input"));
    assert!(js_bundle.contains("Create record"));
    assert!(js_bundle.contains("ensureCollectionDetails"));
    assert!(js_bundle.contains("record-collection-select"));
    assert!(js_bundle.contains("record-empty-collection"));
    assert!(js_bundle.contains("selectRecordCollection"));
    assert!(js_bundle.contains("recordFieldFormHtml"));
    assert!(js_bundle.contains("data-record-field"));
    assert!(js_bundle.contains("collectionIsAuth"));
    assert!(js_bundle.contains("recordEditorFields"));
    assert!(js_bundle.contains("passwordConfirm"));
    assert!(js_bundle.contains("new-password"));
    assert!(js_bundle.contains("syncRecordFieldFromInput"));
    assert!(js_bundle.contains("recordFieldValuePreview"));
    assert!(js_bundle.contains("ensureRelationOptionsForCollection"));
    assert!(js_bundle.contains("relationFieldInputHtml"));
    assert!(js_bundle.contains("relationOptionLabel"));
    assert!(js_bundle.contains("relationTargetCollectionName"));
    assert!(js_bundle.contains("relationFieldValuePreview"));
    assert!(js_bundle.contains("relationDisplayLabel"));
    assert!(js_bundle.contains("data-record-relation-target"));
    assert!(js_bundle.contains("selectedOptions"));
    assert!(js_bundle.contains("Fix record JSON before using field inputs"));
    assert!(js_bundle.contains("recordValidationSummaryHtml"));
    assert!(js_bundle.contains("validationDataFromError"));
    assert!(js_bundle.contains("field-error"));
    assert!(js_bundle.contains("clearRecordValidationFeedback"));
    assert!(js_bundle.contains("error.body"));
    assert!(js_bundle.contains("data-record-file"));
    assert!(js_bundle.contains("recordEditorFileUploads"));
    assert!(js_bundle.contains("recordFormDataPayload"));
    assert!(js_bundle.contains("FormData"));
    assert!(js_bundle.contains("recordFileValueHtml"));
    assert!(js_bundle.contains("filePath"));
    assert!(js_bundle.contains("data-record-file-download"));
    assert!(js_bundle.contains("downloadRecordFile"));
    assert!(js_bundle.contains("URL.createObjectURL"));
    assert!(js_bundle.contains("data-record-file-delete"));
    assert!(js_bundle.contains("recordEditorFileDeletes"));
    assert!(js_bundle.contains("applyRecordFileDeletes"));
    assert!(js_bundle.contains("Initialized and logged in"));
    assert!(js_bundle.contains(r#""PATCH""#));
    assert!(js_bundle.contains(r#"method: "DELETE""#));

    let styles = app.handle(HttpRequest::new("GET", "/_/admin/styles.css"));
    assert_eq!(styles.status, 200);
    assert_eq!(styles.content_type, "text/css; charset=utf-8");
    assert_eq!(
        styles
            .headers
            .get("x-content-type-options")
            .map(String::as_str),
        Some("nosniff")
    );
    let css = String::from_utf8(styles.raw_body).unwrap();
    assert!(css.contains(".shell"));
    assert!(css.contains(".record-form-grid"));

    let missing_asset = app.handle(HttpRequest::new("GET", "/_/admin/missing.js"));
    assert_eq!(missing_asset.status, 404);
    let missing_nested_asset = app.handle(HttpRequest::new("GET", "/_/admin/records/missing.js"));
    assert_eq!(missing_nested_asset.status, 404);

    let health = app.handle(HttpRequest::new("GET", "/api/health"));
    assert_eq!(health.status, 200);
}

#[test]
fn stores_collection_records_and_filters_with_filter_engine() {
    let store = Store::open_in_memory().unwrap();
    store.create_collection(posts_collection()).unwrap();
    store
        .create_record(
            "posts",
            json!({"title": "Rusty Base", "published": true, "owner": "user_1", "score": 10}),
        )
        .unwrap();
    store
        .create_record(
            "posts",
            json!({"title": "Draft note", "published": false, "owner": "user_1", "score": 1}),
        )
        .unwrap();

    let list = store
        .list_records(
            "posts",
            ListOptions {
                filter: Some("published = true && title ~ 'Rusty'".to_string()),
                ..ListOptions::default()
            },
        )
        .unwrap();

    assert_eq!(list.total_items, 1);
    assert_eq!(list.items[0]["title"], "Rusty Base");
}

#[test]
fn uses_pocketbase_style_system_timestamps() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let collection = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [{"name": "title", "type": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(collection.status, 200);
    assert_pocketbase_datetime_value(&collection.body["created"]);
    assert_pocketbase_datetime_value(&collection.body["updated"]);

    let created = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"id": "post_1", "title": "Timestamped"}),
        )
        .unwrap(),
    );
    assert_eq!(created.status, 200);
    assert_pocketbase_datetime_value(&created.body["created"]);
    assert_pocketbase_datetime_value(&created.body["updated"]);

    let updated = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_1",
            json!({"title": "Updated timestamp"}),
        )
        .unwrap(),
    );
    assert_eq!(updated.status, 200);
    assert_pocketbase_datetime_value(&updated.body["created"]);
    assert_pocketbase_datetime_value(&updated.body["updated"]);
}

#[test]
fn applies_list_rule_with_request_auth_context() {
    let store = Store::open_in_memory().unwrap();
    store
        .create_collection(posts_collection().with_list_rule("owner = @request.auth.id"))
        .unwrap();
    store
        .create_record(
            "posts",
            json!({"title": "Mine", "published": true, "owner": "user_1", "score": 3}),
        )
        .unwrap();
    store
        .create_record(
            "posts",
            json!({"title": "Theirs", "published": true, "owner": "user_2", "score": 5}),
        )
        .unwrap();

    let context =
        FilterContext::default().with_auth_value("id", FilterValue::String("user_1".to_string()));
    let list = store
        .list_records(
            "posts",
            ListOptions {
                context,
                ..ListOptions::default()
            },
        )
        .unwrap();

    assert_eq!(list.total_items, 1);
    assert_eq!(list.items[0]["title"], "Mine");
}

#[test]
fn hashes_auth_passwords_and_uses_login_tokens_for_rules() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let users = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "users",
                "type": "auth",
                "fields": [
                    {"name": "email", "kind": "text"},
                    {"name": "name", "kind": "text"}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(users.status, 200);

    let user = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/records",
            json!({
                "email": "burak@example.com",
                "name": "Burak",
                "password": "correct horse",
                "passwordConfirm": "correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(user.status, 200);
    assert_eq!(user.body["email"], "burak@example.com");
    assert!(user.body.get("password").is_none());
    assert!(user.body.get("passwordHash").is_none());
    let user_id = user.body["id"].as_str().unwrap().to_string();

    let denied_login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak@example.com", "password": "wrong password"}),
        )
        .unwrap(),
    );
    assert_eq!(denied_login.status, 400);
    assert_eq!(denied_login.body["code"], 400);
    assert_eq!(denied_login.body["message"], "Failed to authenticate.");
    assert_eq!(denied_login.body["data"], json!({}));

    let login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(login.status, 200);
    let token = login.body["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("rb_"));
    assert!(login.body["expires"]
        .as_str()
        .unwrap()
        .parse::<u128>()
        .is_ok());
    assert_eq!(login.body["record"]["id"], user_id);
    assert!(login.body["record"].get("passwordHash").is_none());

    let admins = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "admins",
                "type": "auth",
                "fields": [{"name": "email", "kind": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(admins.status, 200);

    let wrong_collection_refresh = app.handle(
        HttpRequest::new("POST", "/api/collections/admins/auth-refresh")
            .with_header("Authorization", format!("Bearer {token}")),
    );
    assert_eq!(wrong_collection_refresh.status, 403);
    assert_eq!(wrong_collection_refresh.body["data"], json!({}));

    let wrong_collection_logout = app.handle(
        HttpRequest::new("POST", "/api/collections/admins/auth-logout")
            .with_header("Authorization", format!("Bearer {token}")),
    );
    assert_eq!(wrong_collection_logout.status, 403);

    let refresh = app.handle(
        HttpRequest::new("POST", "/api/collections/users/auth-refresh")
            .with_header("Authorization", format!("Bearer {token}")),
    );
    assert_eq!(refresh.status, 200);
    let refreshed_token = refresh.body["token"].as_str().unwrap().to_string();
    assert_ne!(refreshed_token, token);
    assert_eq!(refresh.body["record"]["id"], user_id);

    let old_token = app.handle(
        HttpRequest::new("POST", "/api/collections/users/auth-refresh")
            .with_header("Authorization", format!("Bearer {token}")),
    );
    assert_eq!(old_token.status, 403);

    let posts = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "title", "kind": "text"},
                    {"name": "published", "kind": "bool"},
                    {"name": "owner", "kind": "text"},
                    {"name": "score", "kind": "number"}
                ],
                "listRule": "owner = @request.auth.id"
            }),
        )
        .unwrap(),
    );
    assert_eq!(posts.status, 200);

    let created = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Token visible", "published": true, "owner": user_id, "score": 9}),
        )
        .unwrap(),
    );
    assert_eq!(created.status, 200);

    let anonymous = app.handle(HttpRequest::new("GET", "/api/collections/posts/records"));
    assert_eq!(anonymous.status, 200);
    assert_eq!(anonymous.body["totalItems"], 0);

    let authorized = app.handle(
        HttpRequest::new("GET", "/api/collections/posts/records")
            .with_header("Authorization", format!("Bearer {refreshed_token}")),
    );
    assert_eq!(authorized.status, 200);
    assert_eq!(authorized.body["totalItems"], 1);
    assert_eq!(authorized.body["items"][0]["title"], "Token visible");

    let logout = app.handle(
        HttpRequest::new("POST", "/api/collections/users/auth-logout")
            .with_header("Authorization", format!("Bearer {refreshed_token}")),
    );
    assert_eq!(logout.status, 204);

    let logged_out = app.handle(
        HttpRequest::new("GET", "/api/collections/posts/records")
            .with_header("Authorization", format!("Bearer {refreshed_token}")),
    );
    assert_eq!(logged_out.status, 200);
    assert_eq!(logged_out.body["totalItems"], 0);

    let second_login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(second_login.status, 200);
    let expiring_token = second_login.body["token"].as_str().unwrap().to_string();

    app.store().expire_token(&expiring_token).unwrap();
    let expired = app.handle(
        HttpRequest::new("GET", "/api/collections/posts/records")
            .with_header("Authorization", format!("Bearer {expiring_token}")),
    );
    assert_eq!(expired.status, 200);
    assert_eq!(expired.body["totalItems"], 0);

    let expired_refresh = app.handle(
        HttpRequest::new("POST", "/api/collections/users/auth-refresh")
            .with_header("Authorization", format!("Bearer {expiring_token}")),
    );
    assert_eq!(expired_refresh.status, 403);
    assert!(expired_refresh.body["message"]
        .as_str()
        .unwrap()
        .contains("expired auth token"));
}

#[test]
fn superusers_manage_collections_and_bypass_record_rules() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let superusers = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "_superusers",
                "type": "auth",
                "fields": [{"name": "email", "kind": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(superusers.status, 200);

    let first_superuser = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/_superusers/records",
            json!({
                "id": "su_1",
                "email": "root@example.com",
                "password": "correct horse",
                "passwordConfirm": "correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(first_superuser.status, 200);

    let blocked_collections = app.handle(HttpRequest::new("GET", "/api/collections"));
    assert_eq!(blocked_collections.status, 403);
    assert!(blocked_collections.body["message"]
        .as_str()
        .unwrap()
        .contains("missing superuser auth token"));

    let blocked_superuser_create = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/_superusers/records",
            json!({
                "email": "other@example.com",
                "password": "correct horse",
                "passwordConfirm": "correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(blocked_superuser_create.status, 403);

    let login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/_superusers/auth-with-password",
            json!({"identity": "root@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(login.status, 200);
    let superuser_token = login.body["token"].as_str().unwrap().to_string();

    let collection_list = app.handle(
        HttpRequest::new("GET", "/api/collections")
            .with_header("Authorization", format!("Bearer {superuser_token}")),
    );
    assert_eq!(collection_list.status, 200);
    assert_eq!(collection_list.body["page"], 1);
    assert_eq!(collection_list.body["perPage"], 30);
    assert_eq!(collection_list.body["totalItems"], 1);
    assert_eq!(collection_list.body["items"][0]["name"], "_superusers");
    assert_eq!(collection_list.body["items"][0]["type"], "auth");
    assert_eq!(collection_list.body["items"][0]["system"], true);

    let posts = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [{"name": "title", "kind": "text"}],
                "listRule": "id = 'never'",
                "viewRule": "id = 'never'",
                "createRule": "title = 'rule-allowed'",
                "updateRule": "title = 'rule-allowed'",
                "deleteRule": "title = 'rule-allowed'"
            }),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {superuser_token}")),
    );
    assert_eq!(posts.status, 200);

    let filtered_collections = app.handle(
        HttpRequest::new(
            "GET",
            "/api/collections?page=1&perPage=1&filter=type='base'&sort=-name&fields=page,perPage,totalItems,totalPages,items.name,items.type,items.system",
        )
        .with_header("Authorization", format!("Bearer {superuser_token}")),
    );
    assert_eq!(filtered_collections.status, 200);
    assert_eq!(filtered_collections.body["page"], 1);
    assert_eq!(filtered_collections.body["perPage"], 1);
    assert_eq!(filtered_collections.body["totalItems"], 1);
    assert_eq!(filtered_collections.body["totalPages"], 1);
    assert_eq!(filtered_collections.body["items"][0]["name"], "posts");
    assert_eq!(filtered_collections.body["items"][0]["type"], "base");
    assert_eq!(filtered_collections.body["items"][0]["system"], false);
    assert!(filtered_collections.body["items"][0]
        .get("fields")
        .is_none());

    let denied_create = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"id": "post_1", "title": "Super Created"}),
        )
        .unwrap(),
    );
    assert_eq!(denied_create.status, 403);

    let created = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"id": "post_1", "title": "Super Created"}),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {superuser_token}")),
    );
    assert_eq!(created.status, 200);
    assert_eq!(created.body["title"], "Super Created");

    let anonymous_list = app.handle(HttpRequest::new("GET", "/api/collections/posts/records"));
    assert_eq!(anonymous_list.status, 200);
    assert_eq!(anonymous_list.body["totalItems"], 0);

    let superuser_list = app.handle(
        HttpRequest::new("GET", "/api/collections/posts/records")
            .with_header("Authorization", format!("Bearer {superuser_token}")),
    );
    assert_eq!(superuser_list.status, 200);
    assert_eq!(superuser_list.body["totalItems"], 1);

    let anonymous_view = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts/records/post_1",
    ));
    assert_eq!(anonymous_view.status, 404);

    let superuser_view = app.handle(
        HttpRequest::new("GET", "/api/collections/posts/records/post_1")
            .with_header("Authorization", format!("Bearer {superuser_token}")),
    );
    assert_eq!(superuser_view.status, 200);
    assert_eq!(superuser_view.body["title"], "Super Created");

    let denied_update = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_1",
            json!({"title": "Anonymous Update"}),
        )
        .unwrap(),
    );
    assert_eq!(denied_update.status, 403);

    let updated = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_1",
            json!({"title": "Super Updated"}),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {superuser_token}")),
    );
    assert_eq!(updated.status, 200);
    assert_eq!(updated.body["title"], "Super Updated");

    let denied_delete = app.handle(HttpRequest::new(
        "DELETE",
        "/api/collections/posts/records/post_1",
    ));
    assert_eq!(denied_delete.status, 403);

    let deleted = app.handle(
        HttpRequest::new("DELETE", "/api/collections/posts/records/post_1")
            .with_header("Authorization", format!("Bearer {superuser_token}")),
    );
    assert_eq!(deleted.status, 204);
}

#[test]
fn manages_settings_and_applies_batch_limits() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let public_defaults = app.handle(HttpRequest::new("GET", "/api/settings"));
    assert_eq!(public_defaults.status, 200);
    assert_eq!(public_defaults.body["meta"]["appName"], "Rusty Base");
    assert_eq!(public_defaults.body["batch"]["maxRequests"], 50);

    let superusers = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "_superusers",
                "type": "auth",
                "fields": [{"name": "email", "kind": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(superusers.status, 200);

    let first_superuser = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/_superusers/records",
            json!({
                "id": "su_1",
                "email": "root@example.com",
                "password": "correct horse",
                "passwordConfirm": "correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(first_superuser.status, 200);

    let blocked = app.handle(HttpRequest::new("GET", "/api/settings"));
    assert_eq!(blocked.status, 403);

    let login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/_superusers/auth-with-password",
            json!({"identity": "root@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(login.status, 200);
    let superuser_token = login.body["token"].as_str().unwrap().to_string();

    let settings = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/settings",
            json!({
                "meta": {
                    "appName": "Acme",
                    "appURL": "https://example.com"
                },
                "batch": {
                    "maxRequests": 1,
                    "maxBodySize": 0
                },
                "smtp": {
                    "enabled": true,
                    "host": "smtp.example.com",
                    "port": 2525,
                    "password": "smtp-secret"
                },
                "s3": {
                    "enabled": true,
                    "bucket": "assets",
                    "region": "auto",
                    "endpoint": "https://s3.example.com",
                    "accessKey": "access",
                    "secret": "s3-secret"
                }
            }),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {superuser_token}")),
    );
    assert_eq!(settings.status, 200);
    assert_eq!(settings.body["meta"]["appName"], "Acme");
    assert_eq!(settings.body["meta"]["appURL"], "https://example.com");
    assert_eq!(settings.body["batch"]["maxRequests"], 1);
    assert_eq!(settings.body["smtp"]["password"], "******");
    assert_eq!(settings.body["s3"]["secret"], "******");

    let redacted_patch = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/settings?fields=smtp.password,s3.secret,batch.maxRequests",
            json!({
                "smtp": {"password": "******"},
                "s3": {"secret": "******"},
                "batch": {"maxRequests": 2}
            }),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {superuser_token}")),
    );
    assert_eq!(redacted_patch.status, 200);
    assert_eq!(redacted_patch.body["smtp"]["password"], "******");
    assert_eq!(redacted_patch.body["s3"]["secret"], "******");
    assert_eq!(redacted_patch.body["batch"]["maxRequests"], 2);
    let stored_settings = app.store().get_settings().unwrap();
    assert_eq!(stored_settings.smtp.password, "smtp-secret");
    assert_eq!(stored_settings.s3.secret, "s3-secret");

    let posts = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [{"name": "title", "kind": "text"}]
            }),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {superuser_token}")),
    );
    assert_eq!(posts.status, 200);

    let limited = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/settings",
            json!({"batch": {"maxRequests": 1}}),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {superuser_token}")),
    );
    assert_eq!(limited.status, 200);

    let too_many = app.handle(
        HttpRequest::json(
            "POST",
            "/api/batch",
            json!({
                "requests": [
                    {
                        "method": "POST",
                        "url": "/api/collections/posts/records",
                        "body": {"id": "post_1", "title": "One"}
                    },
                    {
                        "method": "POST",
                        "url": "/api/collections/posts/records",
                        "body": {"id": "post_2", "title": "Two"}
                    }
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(too_many.status, 400);
    assert_eq!(
        too_many.body["data"]["requests"]["code"],
        "validation_max_items"
    );

    let disabled = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/settings",
            json!({"batch": {"enabled": false}}),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {superuser_token}")),
    );
    assert_eq!(disabled.status, 200);

    let disabled_batch =
        app.handle(HttpRequest::json("POST", "/api/batch", json!({"requests": []})).unwrap());
    assert_eq!(disabled_batch.status, 400);
    assert_eq!(disabled_batch.body["message"], "Batch API is disabled.");
}

#[test]
fn superusers_impersonate_auth_records_with_nonrenewable_tokens() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let superusers = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "_superusers",
                "type": "auth",
                "fields": [{"name": "email", "kind": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(superusers.status, 200);

    let first_superuser = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/_superusers/records",
            json!({
                "id": "su_1",
                "email": "root@example.com",
                "password": "correct horse",
                "passwordConfirm": "correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(first_superuser.status, 200);

    let login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/_superusers/auth-with-password",
            json!({"identity": "root@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(login.status, 200);
    let superuser_token = login.body["token"].as_str().unwrap().to_string();

    let users = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "users",
                "type": "auth",
                "fields": [{"name": "email", "kind": "text"}]
            }),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {superuser_token}")),
    );
    assert_eq!(users.status, 200);

    let user = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/records",
            json!({
                "id": "user_1",
                "email": "burak@example.com",
                "password": "correct horse",
                "passwordConfirm": "correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(user.status, 200);

    let posts = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "title", "kind": "text"},
                    {"name": "owner", "kind": "text"}
                ],
                "listRule": "owner = @request.auth.id"
            }),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {superuser_token}")),
    );
    assert_eq!(posts.status, 200);

    let post = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Impersonated access", "owner": "user_1"}),
        )
        .unwrap(),
    );
    assert_eq!(post.status, 200);

    let blocked = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/impersonate/user_1",
            json!({"duration": 3600}),
        )
        .unwrap(),
    );
    assert_eq!(blocked.status, 403);

    let impersonated = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/impersonate/user_1",
            json!({"duration": 3600}),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {superuser_token}")),
    );
    assert_eq!(impersonated.status, 200);
    assert_eq!(impersonated.body["record"]["id"], "user_1");
    let impersonated_token = impersonated.body["token"].as_str().unwrap().to_string();
    assert!(impersonated.body["expires"]
        .as_str()
        .unwrap()
        .parse::<u128>()
        .is_ok());

    let visible_as_user = app.handle(
        HttpRequest::new("GET", "/api/collections/posts/records")
            .with_header("Authorization", format!("Bearer {impersonated_token}")),
    );
    assert_eq!(visible_as_user.status, 200);
    assert_eq!(visible_as_user.body["totalItems"], 1);
    assert_eq!(
        visible_as_user.body["items"][0]["title"],
        "Impersonated access"
    );

    let refresh = app.handle(
        HttpRequest::new("POST", "/api/collections/users/auth-refresh")
            .with_header("Authorization", format!("Bearer {impersonated_token}")),
    );
    assert_eq!(refresh.status, 403);
    assert!(refresh.body["message"]
        .as_str()
        .unwrap()
        .contains("cannot be refreshed"));

    let non_auth = app.handle(
        HttpRequest::new("POST", "/api/collections/posts/impersonate/user_1")
            .with_header("Authorization", format!("Bearer {superuser_token}")),
    );
    assert_eq!(non_auth.status, 400);
}

#[test]
fn auth_responses_support_expand_and_response_fields() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    for collection in [
        json!({
            "name": "profiles",
            "fields": [
                {"name": "bio", "kind": "text"},
                {"name": "owner", "kind": "text"}
            ],
            "viewRule": "owner = @request.auth.id"
        }),
        json!({
            "name": "users",
            "type": "auth",
            "fields": [
                {"name": "email", "kind": "text"},
                {"name": "name", "kind": "text"},
                {
                    "name": "profile",
                    "kind": "relation",
                    "collection": "profiles",
                    "maxSelect": 1
                }
            ]
        }),
    ] {
        let response =
            app.handle(HttpRequest::json("POST", "/api/collections", collection).unwrap());
        assert_eq!(response.status, 200);
    }

    let profile = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/profiles/records",
            json!({"id": "profile_1", "bio": "Private profile", "owner": "user_1"}),
        )
        .unwrap(),
    );
    assert_eq!(profile.status, 200);

    let user = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/records",
            json!({
                "id": "user_1",
                "email": "burak@example.com",
                "name": "Burak",
                "profile": "profile_1",
                "password": "correct horse",
                "passwordConfirm": "correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(user.status, 200);

    let login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password?expand=profile&fields=*,record.expand.profile.bio",
            json!({"identity": "burak@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(login.status, 200);
    let token = login.body["token"].as_str().unwrap().to_string();
    assert!(login.body["expires"]
        .as_str()
        .unwrap()
        .parse::<u128>()
        .is_ok());
    assert_eq!(login.body["record"]["id"], "user_1");
    assert_eq!(login.body["record"]["email"], "burak@example.com");
    assert_eq!(
        login.body["record"]["expand"]["profile"]["bio"],
        "Private profile"
    );
    assert!(login.body["record"]["expand"]["profile"]
        .get("owner")
        .is_none());

    let refresh = app.handle(
        HttpRequest::new(
            "POST",
            "/api/collections/users/auth-refresh?expand=profile&fields=token,record.email,record.expand.profile.bio",
        )
        .with_header("Authorization", format!("Bearer {token}")),
    );
    assert_eq!(refresh.status, 200);
    assert_ne!(refresh.body["token"], token);
    assert!(refresh.body.get("expires").is_none());
    assert_eq!(refresh.body["record"]["email"], "burak@example.com");
    assert!(refresh.body["record"].get("id").is_none());
    assert_eq!(
        refresh.body["record"]["expand"]["profile"]["bio"],
        "Private profile"
    );
    assert!(refresh.body["record"]["expand"]["profile"]
        .get("owner")
        .is_none());
}

#[test]
fn lists_auth_methods_and_projects_auth_method_fields() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let users = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "users",
                "type": "auth",
                "fields": [
                    {"name": "email", "type": "email"},
                    {"name": "username", "kind": "text"},
                    {"name": "name", "kind": "text"}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(users.status, 200);
    let email_field = collection_field(&users.body, "email");
    assert_eq!(email_field["type"], "email");
    assert!(email_field.get("kind").is_none());

    let methods = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/users/auth-methods",
    ));
    assert_eq!(methods.status, 200);
    assert_eq!(methods.body["password"]["enabled"], true);
    assert_eq!(
        methods.body["password"]["identityFields"],
        json!(["email", "username"])
    );
    assert_eq!(methods.body["oauth2"]["enabled"], false);
    assert_eq!(methods.body["oauth2"]["providers"], json!([]));
    assert_eq!(methods.body["authProviders"], json!([]));
    assert_eq!(methods.body["emailPassword"], true);
    assert_eq!(methods.body["usernamePassword"], true);
    assert_eq!(methods.body["mfa"]["enabled"], false);
    assert_eq!(methods.body["otp"]["enabled"], true);
    assert_eq!(methods.body["otp"]["duration"], 180);

    let projected = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/users/auth-methods?fields=password.identityFields,otp.enabled",
    ));
    assert_eq!(projected.status, 200);
    assert_eq!(
        projected.body["password"]["identityFields"],
        json!(["email", "username"])
    );
    assert_eq!(projected.body["otp"]["enabled"], true);
    assert!(projected.body.get("oauth2").is_none());
    assert!(projected.body["otp"].get("duration").is_none());

    let posts = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [{"name": "title", "kind": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(posts.status, 200);

    let not_auth = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts/auth-methods",
    ));
    assert_eq!(not_auth.status, 400);
    assert!(not_auth.body["message"]
        .as_str()
        .unwrap()
        .contains("not an auth collection"));
}

#[test]
fn persists_auth_options_and_supports_oauth2_profile_linking() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());
    let fixture_provider = spawn_oauth2_fixture_provider();

    let users = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "users",
                "type": "auth",
                "fields": [
                    {"name": "email", "type": "email"},
                    {"name": "username", "kind": "text"},
                    {"name": "name", "kind": "text"},
                    {"name": "verified", "kind": "bool"},
                    {"name": "emailVisibility", "kind": "bool"}
                ],
                "passwordAuth": {
                    "enabled": true,
                    "identityFields": ["username"]
                },
                "oauth2": {
                    "enabled": true,
                    "providers": [
                        {
                            "name": "github",
                            "displayName": "GitHub",
                            "clientId": "client-id",
                            "clientSecret": "client-secret"
                        },
                        {
                            "name": "custom",
                            "displayName": "Custom",
                            "clientId": "client-id",
                            "clientSecret": "client-secret",
                            "authUrl": "https://auth.example.test/oauth/authorize",
                            "scopes": ["identity", "email"]
                        },
                        {
                            "name": "fixture",
                            "displayName": "Fixture",
                            "clientId": "fixture-client",
                            "clientSecret": "fixture-secret",
                            "tokenUrl": fixture_provider.token_url.clone(),
                            "userInfoUrl": fixture_provider.user_info_url.clone()
                        }
                    ]
                },
                "otp": {
                    "enabled": false,
                    "duration": 240,
                    "length": 10
                }
            }),
        )
        .unwrap(),
    );
    assert_eq!(users.status, 200);
    assert_eq!(
        users.body["passwordAuth"]["identityFields"],
        json!(["username"])
    );
    assert_eq!(users.body["oauth2"]["providers"][0]["name"], "github");
    assert_eq!(
        users.body["oauth2"]["providers"][1]["authUrl"],
        "https://auth.example.test/oauth/authorize"
    );
    assert_eq!(
        users.body["oauth2"]["providers"][1]["scopes"],
        json!(["identity", "email"])
    );
    assert_eq!(users.body["otp"]["enabled"], false);

    let methods = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/users/auth-methods",
    ));
    assert_eq!(methods.status, 200);
    assert_eq!(
        methods.body["password"]["identityFields"],
        json!(["username"])
    );
    assert_eq!(methods.body["emailPassword"], false);
    assert_eq!(methods.body["usernamePassword"], true);
    assert_eq!(methods.body["otp"]["enabled"], false);
    assert_eq!(methods.body["oauth2"]["enabled"], true);
    assert_eq!(methods.body["oauth2"]["providers"][0]["name"], "github");
    assert_eq!(
        methods.body["oauth2"]["providers"][0]["displayName"],
        "GitHub"
    );
    assert_eq!(methods.body["authProviders"][0]["name"], "github");
    let github_provider = &methods.body["oauth2"]["providers"][0];
    let github_state = github_provider["state"].as_str().unwrap();
    let github_verifier = github_provider["codeVerifier"].as_str().unwrap();
    let github_challenge = github_provider["codeChallenge"].as_str().unwrap();
    let github_auth_url = github_provider["authURL"].as_str().unwrap();
    assert_eq!(github_provider["codeChallengeMethod"], "S256");
    assert_eq!(github_state.len(), 32);
    assert_eq!(github_verifier.len(), 43);
    assert_eq!(github_challenge.len(), 43);
    assert!(github_auth_url.starts_with("https://github.com/login/oauth/authorize?"));
    assert!(github_auth_url.contains("client_id=client-id"));
    assert!(github_auth_url.contains("scope=read%3Auser+user%3Aemail"));
    assert!(github_auth_url.contains(&format!("state={github_state}")));
    assert!(github_auth_url.contains(&format!("code_challenge={github_challenge}")));

    let custom_provider = &methods.body["oauth2"]["providers"][1];
    let custom_state = custom_provider["state"].as_str().unwrap();
    let custom_challenge = custom_provider["codeChallenge"].as_str().unwrap();
    let custom_auth_url = custom_provider["authURL"].as_str().unwrap();
    assert!(custom_auth_url.starts_with("https://auth.example.test/oauth/authorize?"));
    assert!(custom_auth_url.contains("scope=identity+email"));
    assert!(custom_auth_url.contains(&format!("state={custom_state}")));
    assert!(custom_auth_url.contains(&format!("code_challenge={custom_challenge}")));
    assert_eq!(custom_provider["codeChallengeMethod"], "S256");

    let user = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/records",
            json!({
                "id": "user_1",
                "email": "burak@example.com",
                "username": "burak",
                "password": "correct horse",
                "passwordConfirm": "correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(user.status, 200);

    let email_login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(email_login.status, 400);

    let username_login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(username_login.status, 200);

    let missing_provider = app.handle(
        HttpRequest::json("POST", "/api/collections/users/auth-with-oauth2", json!({})).unwrap(),
    );
    assert_eq!(missing_provider.status, 400);
    assert_eq!(
        missing_provider.body["data"]["provider"]["code"],
        "validation_required"
    );

    let unknown_provider = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-oauth2",
            json!({
                "provider": "google",
                "code": "code",
                "codeVerifier": "verifier",
                "redirectUrl": "http://127.0.0.1/callback"
            }),
        )
        .unwrap(),
    );
    assert_eq!(unknown_provider.status, 400);
    assert!(unknown_provider.body["message"]
        .as_str()
        .unwrap()
        .contains("not configured"));

    let opaque_provider = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-oauth2",
            json!({
                "provider": "custom",
                "code": "code",
                "codeVerifier": "verifier",
                "redirectUrl": "http://127.0.0.1/callback",
                "createData": {"name": "Burak"}
            }),
        )
        .unwrap(),
    );
    assert_eq!(opaque_provider.status, 400);
    assert!(opaque_provider.body["message"]
        .as_str()
        .unwrap()
        .contains("callback exchange is not configured"));

    let remote_provider = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-oauth2?fields=record.email,record.username,record.name,meta.id,meta.provider,meta.accessToken,meta.refreshToken,meta.expiry",
            json!({
                "provider": "fixture",
                "code": "remote_code",
                "codeVerifier": "remote_verifier",
                "redirectUrl": "http://127.0.0.1/callback",
                "createData": {"name": "Remote Create"}
            }),
        )
        .unwrap(),
    );
    assert_eq!(remote_provider.status, 200);
    assert_eq!(
        remote_provider.body["record"]["email"],
        "remote@example.com"
    );
    assert_eq!(remote_provider.body["record"]["username"], "remote_user");
    assert_eq!(remote_provider.body["record"]["name"], "Remote Create");
    assert_eq!(remote_provider.body["meta"]["provider"], "fixture");
    assert_eq!(remote_provider.body["meta"]["id"], "42");
    assert_eq!(remote_provider.body["meta"]["accessToken"], "remote_access");
    assert_eq!(
        remote_provider.body["meta"]["refreshToken"],
        "remote_refresh"
    );
    assert_eq!(remote_provider.body["meta"]["expiry"], "3600");
    fixture_provider.handle.join().unwrap();

    let linked_profile_code = json!({
        "id": "gh_1",
        "email": "burak@example.com",
        "username": "github_burak",
        "name": "Burak GitHub",
        "accessToken": "access-token",
        "rawUser": {"login": "github_burak"}
    })
    .to_string();
    let linked_provider = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-oauth2?fields=token,record.id,record.email,meta.id,meta.email,meta.isNew,meta.provider,meta.accessToken",
            json!({
                "provider": "github",
                "code": linked_profile_code,
                "codeVerifier": "verifier",
                "redirectUrl": "http://127.0.0.1/callback",
                "createData": {"name": "Ignored"}
            }),
        )
        .unwrap(),
    );
    assert_eq!(linked_provider.status, 200);
    assert!(linked_provider.body["token"]
        .as_str()
        .unwrap()
        .starts_with("rb_"));
    assert_eq!(linked_provider.body["record"]["id"], "user_1");
    assert_eq!(linked_provider.body["record"]["email"], "burak@example.com");
    assert_eq!(linked_provider.body["meta"]["provider"], "github");
    assert_eq!(linked_provider.body["meta"]["id"], "gh_1");
    assert_eq!(linked_provider.body["meta"]["email"], "burak@example.com");
    assert_eq!(linked_provider.body["meta"]["isNew"], false);
    assert_eq!(linked_provider.body["meta"]["accessToken"], "access-token");

    let repeated_profile_code = json!({
        "id": "gh_1",
        "email": "changed@example.com"
    })
    .to_string();
    let repeated_provider = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-oauth2?fields=record.id,meta.isNew,meta.email",
            json!({
                "provider": "github",
                "code": repeated_profile_code,
                "codeVerifier": "verifier",
                "redirectUrl": "http://127.0.0.1/callback"
            }),
        )
        .unwrap(),
    );
    assert_eq!(repeated_provider.status, 200);
    assert_eq!(repeated_provider.body["record"]["id"], "user_1");
    assert_eq!(repeated_provider.body["meta"]["isNew"], false);
    assert_eq!(
        repeated_provider.body["meta"]["email"],
        "changed@example.com"
    );

    let new_profile_code = json!({
        "id": "gh_2",
        "email": "oauth@example.com",
        "username": "oauth_user",
        "name": "OAuth User"
    })
    .to_string();
    let new_provider = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-oauth2?fields=record.email,record.username,record.name,record.verified,record.emailVisibility,meta.isNew",
            json!({
                "provider": "github",
                "code": new_profile_code,
                "codeVerifier": "verifier",
                "redirectUrl": "http://127.0.0.1/callback"
            }),
        )
        .unwrap(),
    );
    assert_eq!(new_provider.status, 200);
    assert_eq!(new_provider.body["record"]["email"], "oauth@example.com");
    assert_eq!(new_provider.body["record"]["username"], "oauth_user");
    assert_eq!(new_provider.body["record"]["name"], "OAuth User");
    assert_eq!(new_provider.body["record"]["verified"], true);
    assert_eq!(new_provider.body["record"]["emailVisibility"], false);
    assert_eq!(new_provider.body["meta"]["isNew"], true);

    let exported = app.handle(HttpRequest::new("GET", "/api/collections/meta/export"));
    assert_eq!(exported.status, 200);
    assert_eq!(
        exported.body["collections"][0]["passwordAuth"]["identityFields"],
        json!(["username"])
    );
    assert_eq!(
        exported.body["collections"][0]["oauth2"]["providers"][0]["clientId"],
        "client-id"
    );
    assert_eq!(exported.body["collections"][0]["otp"]["length"], 10);
}

#[test]
fn supports_otp_request_and_auth_flow() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let users = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "users",
                "type": "auth",
                "fields": [
                    {"name": "email", "type": "email"},
                    {"name": "name", "kind": "text"},
                    {"name": "verified", "kind": "bool"}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(users.status, 200);

    let user = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/records",
            json!({
                "id": "user_1",
                "email": "burak@example.com",
                "name": "Burak",
                "verified": false,
                "password": "correct horse",
                "passwordConfirm": "correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(user.status, 200);

    let missing_email = app.handle(
        HttpRequest::json("POST", "/api/collections/users/request-otp", json!({})).unwrap(),
    );
    assert_eq!(missing_email.status, 400);
    assert_eq!(
        missing_email.body["data"]["email"]["code"],
        "validation_required"
    );

    let invalid_email = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/request-otp",
            json!({"email": "not-an-email"}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_email.status, 400);
    assert_eq!(
        invalid_email.body["data"]["email"]["code"],
        "validation_is_email"
    );

    let unknown_email = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/request-otp",
            json!({"email": "missing@example.com"}),
        )
        .unwrap(),
    );
    assert_eq!(unknown_email.status, 200);
    assert!(unknown_email.body["otpId"].as_str().is_some());

    let unknown_auth = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-otp",
            json!({"otpId": unknown_email.body["otpId"], "password": "000000"}),
        )
        .unwrap(),
    );
    assert_eq!(unknown_auth.status, 400);
    assert_eq!(unknown_auth.body["message"], "Failed to authenticate.");

    let request_otp = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/request-otp",
            json!({"email": "burak@example.com"}),
        )
        .unwrap(),
    );
    assert_eq!(request_otp.status, 200);
    let otp_id = request_otp.body["otpId"].as_str().unwrap().to_string();
    assert_eq!(
        app.store()
            .latest_auth_action_token("users", "user_1", "otp")
            .unwrap()
            .as_deref(),
        Some(otp_id.as_str())
    );
    let otp_data = app
        .store()
        .latest_auth_action_data("users", "user_1", "otp")
        .unwrap()
        .unwrap();
    let password = otp_data["password"].as_str().unwrap().to_string();
    assert_eq!(password.len(), 8);

    let missing_otp_id = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-otp",
            json!({"password": password.clone()}),
        )
        .unwrap(),
    );
    assert_eq!(missing_otp_id.status, 400);
    assert_eq!(
        missing_otp_id.body["data"]["otpId"]["code"],
        "validation_required"
    );

    let wrong_password = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-otp",
            json!({"otpId": otp_id.clone(), "password": "999999"}),
        )
        .unwrap(),
    );
    assert_eq!(wrong_password.status, 400);
    assert_eq!(wrong_password.body["message"], "Failed to authenticate.");

    let auth = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-otp?fields=token,record.email,record.verified",
            json!({"otpId": otp_id.clone(), "password": password.clone()}),
        )
        .unwrap(),
    );
    assert_eq!(auth.status, 200);
    assert!(auth.body["token"].as_str().unwrap().starts_with("rb_"));
    assert_eq!(auth.body["record"]["email"], "burak@example.com");
    assert_eq!(auth.body["record"]["verified"], true);
    assert!(auth.body.get("expires").is_none());

    let reused_otp = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-otp",
            json!({"otpId": otp_id, "password": password}),
        )
        .unwrap(),
    );
    assert_eq!(reused_otp.status, 400);
}

#[test]
fn expired_otp_token_is_rejected_without_authenticating() {
    let path = temp_db_path("expired-otp-token");
    let app = RustyBaseApp::new(Store::open(&path).unwrap());

    let users = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "users",
                "type": "auth",
                "fields": [
                    {"name": "email", "type": "email"},
                    {"name": "name", "kind": "text"},
                    {"name": "verified", "kind": "bool"}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(users.status, 200);

    let user = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/records",
            json!({
                "id": "user_1",
                "email": "burak@example.com",
                "name": "Burak",
                "verified": false,
                "password": "correct horse",
                "passwordConfirm": "correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(user.status, 200);

    let request_otp = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/request-otp",
            json!({"email": "burak@example.com"}),
        )
        .unwrap(),
    );
    assert_eq!(request_otp.status, 200);
    let otp_id = request_otp.body["otpId"].as_str().unwrap().to_string();
    let otp_data = app
        .store()
        .latest_auth_action_data("users", "user_1", "otp")
        .unwrap()
        .unwrap();
    let password = otp_data["password"].as_str().unwrap().to_string();

    {
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            r#"UPDATE "_rb_auth_action_tokens" SET expires = ?1 WHERE token = ?2"#,
            params!["0", &otp_id],
        )
        .unwrap();
    }

    let expired_otp = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-otp",
            json!({"otpId": otp_id, "password": password}),
        )
        .unwrap(),
    );
    assert_eq!(expired_otp.status, 400);
    assert_eq!(expired_otp.body["message"], "Failed to authenticate.");
    assert!(app
        .store()
        .latest_auth_action_token("users", "user_1", "otp")
        .unwrap()
        .is_none());

    let record = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/users/records/user_1",
    ));
    assert_eq!(record.status, 200);
    assert_eq!(record.body["verified"], false);

    let password_login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(password_login.status, 200);
    assert_eq!(password_login.body["record"]["verified"], false);

    drop(app);
    fs::remove_file(path).ok();
}

#[test]
fn supports_verification_and_password_reset_tokens() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let users = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "users",
                "type": "auth",
                "fields": [
                    {"name": "email", "type": "email"},
                    {"name": "name", "kind": "text"},
                    {"name": "verified", "kind": "bool"}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(users.status, 200);

    let user = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/records",
            json!({
                "id": "user_1",
                "email": "burak@example.com",
                "name": "Burak",
                "verified": false,
                "password": "correct horse",
                "passwordConfirm": "correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(user.status, 200);

    let old_login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(old_login.status, 200);
    let old_token = old_login.body["token"].as_str().unwrap().to_string();

    let missing_email = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/request-verification",
            json!({}),
        )
        .unwrap(),
    );
    assert_eq!(missing_email.status, 400);
    assert_eq!(
        missing_email.body["data"]["email"]["code"],
        "validation_required"
    );

    let unknown_email = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/request-verification",
            json!({"email": "missing@example.com"}),
        )
        .unwrap(),
    );
    assert_eq!(unknown_email.status, 204);

    let request_verification = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/request-verification",
            json!({"email": "burak@example.com"}),
        )
        .unwrap(),
    );
    assert_eq!(request_verification.status, 204);
    let verification_token = app
        .store()
        .latest_auth_action_token("users", "user_1", "verification")
        .unwrap()
        .unwrap();

    let confirm_verification = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/confirm-verification",
            json!({"token": verification_token}),
        )
        .unwrap(),
    );
    assert_eq!(confirm_verification.status, 204);

    let verified = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/users/records/user_1",
    ));
    assert_eq!(verified.status, 200);
    assert_eq!(verified.body["verified"], true);

    let reused_verification = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/confirm-verification",
            json!({"token": verification_token}),
        )
        .unwrap(),
    );
    assert_eq!(reused_verification.status, 400);

    let request_reset = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/request-password-reset",
            json!({"email": "burak@example.com"}),
        )
        .unwrap(),
    );
    assert_eq!(request_reset.status, 204);
    let reset_token = app
        .store()
        .latest_auth_action_token("users", "user_1", "passwordReset")
        .unwrap()
        .unwrap();

    let mismatch = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/confirm-password-reset",
            json!({
                "token": reset_token,
                "password": "new correct horse",
                "passwordConfirm": "different horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(mismatch.status, 400);
    assert_eq!(
        mismatch.body["data"]["passwordConfirm"]["code"],
        "validation_values_mismatch"
    );

    let confirm_reset = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/confirm-password-reset",
            json!({
                "token": reset_token,
                "password": "new correct horse",
                "passwordConfirm": "new correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(confirm_reset.status, 204);

    let old_token_refresh = app.handle(
        HttpRequest::new("POST", "/api/collections/users/auth-refresh")
            .with_header("Authorization", format!("Bearer {old_token}")),
    );
    assert_eq!(old_token_refresh.status, 403);

    let old_password = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(old_password.status, 400);

    let new_password = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak@example.com", "password": "new correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(new_password.status, 200);
}

#[test]
fn expired_verification_token_is_rejected_without_verifying_record() {
    let path = temp_db_path("expired-verification-token");
    let app = RustyBaseApp::new(Store::open(&path).unwrap());

    let users = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "users",
                "type": "auth",
                "fields": [
                    {"name": "email", "type": "email"},
                    {"name": "name", "kind": "text"},
                    {"name": "verified", "kind": "bool"}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(users.status, 200);

    let user = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/records",
            json!({
                "id": "user_1",
                "email": "burak@example.com",
                "name": "Burak",
                "verified": false,
                "password": "correct horse",
                "passwordConfirm": "correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(user.status, 200);

    let request_verification = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/request-verification",
            json!({"email": "burak@example.com"}),
        )
        .unwrap(),
    );
    assert_eq!(request_verification.status, 204);
    let verification_token = app
        .store()
        .latest_auth_action_token("users", "user_1", "verification")
        .unwrap()
        .unwrap();

    {
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            r#"UPDATE "_rb_auth_action_tokens" SET expires = ?1 WHERE token = ?2"#,
            params!["0", &verification_token],
        )
        .unwrap();
    }

    let expired_verification = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/confirm-verification",
            json!({"token": verification_token}),
        )
        .unwrap(),
    );
    assert_eq!(expired_verification.status, 400);
    assert!(expired_verification.body["message"]
        .as_str()
        .unwrap()
        .contains("invalid or expired verification token"));
    assert!(app
        .store()
        .latest_auth_action_token("users", "user_1", "verification")
        .unwrap()
        .is_none());

    let record = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/users/records/user_1",
    ));
    assert_eq!(record.status, 200);
    assert_eq!(record.body["verified"], false);

    drop(app);
    fs::remove_file(path).ok();
}

#[test]
fn expired_password_reset_token_is_rejected_without_changing_password() {
    let path = temp_db_path("expired-password-reset-token");
    let app = RustyBaseApp::new(Store::open(&path).unwrap());

    let users = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "users",
                "type": "auth",
                "fields": [
                    {"name": "email", "type": "email"},
                    {"name": "name", "kind": "text"}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(users.status, 200);

    let user = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/records",
            json!({
                "id": "user_1",
                "email": "burak@example.com",
                "name": "Burak",
                "password": "correct horse",
                "passwordConfirm": "correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(user.status, 200);

    let request_reset = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/request-password-reset",
            json!({"email": "burak@example.com"}),
        )
        .unwrap(),
    );
    assert_eq!(request_reset.status, 204);
    let reset_token = app
        .store()
        .latest_auth_action_token("users", "user_1", "passwordReset")
        .unwrap()
        .unwrap();

    {
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            r#"UPDATE "_rb_auth_action_tokens" SET expires = ?1 WHERE token = ?2"#,
            params!["0", &reset_token],
        )
        .unwrap();
    }

    let expired_reset = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/confirm-password-reset",
            json!({
                "token": reset_token,
                "password": "new correct horse",
                "passwordConfirm": "new correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(expired_reset.status, 400);
    assert!(expired_reset.body["message"]
        .as_str()
        .unwrap()
        .contains("invalid or expired passwordReset token"));
    assert!(app
        .store()
        .latest_auth_action_token("users", "user_1", "passwordReset")
        .unwrap()
        .is_none());

    let old_password = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(old_password.status, 200);

    let new_password = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak@example.com", "password": "new correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(new_password.status, 400);

    drop(app);
    fs::remove_file(path).ok();
}

#[test]
fn supports_email_change_tokens() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let users = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "users",
                "type": "auth",
                "fields": [
                    {"name": "email", "type": "email"},
                    {"name": "name", "kind": "text"},
                    {"name": "verified", "kind": "bool"}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(users.status, 200);

    let user = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/records",
            json!({
                "id": "user_1",
                "email": "burak@example.com",
                "name": "Burak",
                "verified": false,
                "password": "correct horse",
                "passwordConfirm": "correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(user.status, 200);

    let other_user = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/records",
            json!({
                "id": "user_2",
                "email": "taken@example.com",
                "name": "Taken",
                "verified": true,
                "password": "correct horse",
                "passwordConfirm": "correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(other_user.status, 200);

    let login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(login.status, 200);
    let old_token = login.body["token"].as_str().unwrap().to_string();

    let missing_auth = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/request-email-change",
            json!({"newEmail": "fresh@example.com"}),
        )
        .unwrap(),
    );
    assert_eq!(missing_auth.status, 403);

    let missing_new_email = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/request-email-change",
            json!({}),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {old_token}")),
    );
    assert_eq!(missing_new_email.status, 400);
    assert_eq!(
        missing_new_email.body["data"]["newEmail"]["code"],
        "validation_required"
    );

    let taken_email = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/request-email-change",
            json!({"newEmail": "taken@example.com"}),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {old_token}")),
    );
    assert_eq!(taken_email.status, 400);
    assert_eq!(
        taken_email.body["data"]["newEmail"]["code"],
        "validation_not_unique"
    );

    let request_change = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/request-email-change",
            json!({"newEmail": " changed@example.com "}),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {old_token}")),
    );
    assert_eq!(request_change.status, 204);
    let change_token = app
        .store()
        .latest_auth_action_token("users", "user_1", "emailChange")
        .unwrap()
        .unwrap();

    let wrong_password = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/confirm-email-change",
            json!({"token": change_token.clone(), "password": "wrong password"}),
        )
        .unwrap(),
    );
    assert_eq!(wrong_password.status, 400);
    assert_eq!(wrong_password.body["message"], "Failed to authenticate.");

    let confirm_change = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/confirm-email-change",
            json!({"token": change_token.clone(), "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(confirm_change.status, 204);

    let old_token_refresh = app.handle(
        HttpRequest::new("POST", "/api/collections/users/auth-refresh")
            .with_header("Authorization", format!("Bearer {old_token}")),
    );
    assert_eq!(old_token_refresh.status, 403);

    let old_email_login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(old_email_login.status, 400);

    let new_email_login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "changed@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(new_email_login.status, 200);
    assert_eq!(
        new_email_login.body["record"]["email"],
        "changed@example.com"
    );
    assert_eq!(new_email_login.body["record"]["verified"], true);

    let reused_token = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/confirm-email-change",
            json!({"token": change_token, "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(reused_token.status, 400);
}

#[test]
fn expired_email_change_token_is_rejected_without_changing_email() {
    let path = temp_db_path("expired-email-change-token");
    let app = RustyBaseApp::new(Store::open(&path).unwrap());

    let users = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "users",
                "type": "auth",
                "fields": [
                    {"name": "email", "type": "email"},
                    {"name": "name", "kind": "text"},
                    {"name": "verified", "kind": "bool"}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(users.status, 200);

    let user = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/records",
            json!({
                "id": "user_1",
                "email": "burak@example.com",
                "name": "Burak",
                "verified": false,
                "password": "correct horse",
                "passwordConfirm": "correct horse"
            }),
        )
        .unwrap(),
    );
    assert_eq!(user.status, 200);

    let login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(login.status, 200);
    let old_token = login.body["token"].as_str().unwrap().to_string();

    let request_change = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/request-email-change",
            json!({"newEmail": "changed@example.com"}),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {old_token}")),
    );
    assert_eq!(request_change.status, 204);
    let change_token = app
        .store()
        .latest_auth_action_token("users", "user_1", "emailChange")
        .unwrap()
        .unwrap();

    {
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            r#"UPDATE "_rb_auth_action_tokens" SET expires = ?1 WHERE token = ?2"#,
            params!["0", &change_token],
        )
        .unwrap();
    }

    let expired_change = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/confirm-email-change",
            json!({"token": change_token, "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(expired_change.status, 400);
    assert!(expired_change.body["message"]
        .as_str()
        .unwrap()
        .contains("invalid or expired emailChange token"));
    assert!(app
        .store()
        .latest_auth_action_token("users", "user_1", "emailChange")
        .unwrap()
        .is_none());

    let old_token_refresh = app.handle(
        HttpRequest::new("POST", "/api/collections/users/auth-refresh")
            .with_header("Authorization", format!("Bearer {old_token}")),
    );
    assert_eq!(old_token_refresh.status, 200);

    let old_email_login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(old_email_login.status, 200);
    assert_eq!(old_email_login.body["record"]["email"], "burak@example.com");
    assert_eq!(old_email_login.body["record"]["verified"], false);

    let new_email_login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "changed@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(new_email_login.status, 400);

    drop(app);
    fs::remove_file(path).ok();
}

#[test]
fn returns_validation_data_for_auth_and_record_forms() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let users = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "users",
                "type": "auth",
                "fields": [{"name": "email", "kind": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(users.status, 200);

    let missing_login_password = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak@example.com"}),
        )
        .unwrap(),
    );
    assert_eq!(missing_login_password.status, 400);
    assert_eq!(
        missing_login_password.body["message"],
        "Failed to authenticate."
    );
    assert_eq!(
        missing_login_password.body["data"]["password"]["code"],
        "validation_required"
    );

    let missing_signup_password = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/records",
            json!({"email": "burak@example.com"}),
        )
        .unwrap(),
    );
    assert_eq!(missing_signup_password.status, 400);
    assert_eq!(
        missing_signup_password.body["data"]["password"]["code"],
        "validation_required"
    );

    let posts = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [{"name": "title", "kind": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(posts.status, 200);

    let unknown_field = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Rusty Base", "role": "admin"}),
        )
        .unwrap(),
    );
    assert_eq!(unknown_field.status, 400);
    assert_eq!(unknown_field.body["message"], "Failed to validate record.");
    assert_eq!(
        unknown_field.body["data"]["role"]["code"],
        "validation_unknown_field"
    );
}

#[test]
fn migrates_legacy_auth_tokens_with_expiration() {
    let path = temp_db_path("legacy-auth-tokens");
    let now = test_now_millis();

    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE "_rb_auth_tokens" (
                token TEXT PRIMARY KEY NOT NULL,
                collection_name TEXT NOT NULL,
                record_id TEXT NOT NULL,
                created TEXT NOT NULL
            );
            CREATE TABLE "_rb_collections" (
                name TEXT PRIMARY KEY NOT NULL,
                schema_json TEXT NOT NULL,
                created TEXT NOT NULL,
                updated TEXT NOT NULL
            );
            CREATE TABLE "_rb_records_users" (
                id TEXT PRIMARY KEY NOT NULL,
                data TEXT NOT NULL,
                created TEXT NOT NULL,
                updated TEXT NOT NULL
            );
            "#,
        )
        .unwrap();
        conn.execute(
            r#"
            INSERT INTO "_rb_collections" (name, schema_json, created, updated)
            VALUES (?1, ?2, ?3, ?3)
            "#,
            params![
                "users",
                serde_json::to_string(&CollectionConfig::auth(
                    "users",
                    [CollectionField::new("email", CollectionFieldKind::Email)]
                ))
                .unwrap(),
                now.to_string()
            ],
        )
        .unwrap();
        conn.execute(
            r#"
            INSERT INTO "_rb_auth_tokens" (token, collection_name, record_id, created)
            VALUES (?1, ?2, ?3, ?4)
            "#,
            params!["legacy_token", "users", "user_1", now.to_string()],
        )
        .unwrap();
        conn.execute(
            r#"
            INSERT INTO "_rb_records_users" (id, data, created, updated)
            VALUES (?1, ?2, ?3, ?3)
            "#,
            params![
                "user_1",
                json!({"email": "legacy@example.com"}).to_string(),
                now.to_string()
            ],
        )
        .unwrap();
    }

    let store = Store::open(&path).unwrap();
    let context = store
        .context_for_token("legacy_token", FilterContext::default())
        .unwrap();
    assert_eq!(
        context.request.auth.get("id"),
        Some(&FilterValue::String("user_1".to_string()))
    );
    drop(store);

    let conn = Connection::open(&path).unwrap();
    let expires: String = conn
        .query_row(
            r#"SELECT expires FROM "_rb_auth_tokens" WHERE token = ?1"#,
            params!["legacy_token"],
            |row| row.get(0),
        )
        .unwrap();
    assert!(expires.parse::<u128>().unwrap() > now);
    fs::remove_file(path).ok();
}

#[test]
fn applies_create_rule_against_request_body_and_auth_context() {
    let store = Store::open_in_memory().unwrap();
    store
        .create_collection(
            posts_collection().with_create_rule("@request.body.owner = @request.auth.id"),
        )
        .unwrap();

    let denied = store
        .create_record_with_context(
            "posts",
            json!({"title": "Denied", "published": true, "owner": "user_1", "score": 3}),
            FilterContext::default(),
        )
        .unwrap_err();
    assert!(
        denied.to_string().contains("create rule denied"),
        "{denied}"
    );

    let context =
        FilterContext::default().with_auth_value("id", FilterValue::String("user_1".to_string()));
    let record = store
        .create_record_with_context(
            "posts",
            json!({"title": "Allowed", "published": true, "owner": "user_1", "score": 3}),
            context,
        )
        .unwrap();

    assert_eq!(record["title"], "Allowed");
}

fn temp_db_path(name: &str) -> PathBuf {
    env::temp_dir().join(format!(
        "rusty-base-{name}-{}-{}.db",
        process::id(),
        test_now_millis()
    ))
}

fn test_now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[test]
fn applies_update_and_delete_rules_against_existing_records() {
    let store = Store::open_in_memory().unwrap();
    store
        .create_collection(
            posts_collection()
                .with_update_rule("owner = @request.auth.id")
                .with_delete_rule("owner = @request.auth.id"),
        )
        .unwrap();
    store
        .create_record(
            "posts",
            json!({"id": "post_1", "title": "Mine", "published": true, "owner": "user_1", "score": 3}),
        )
        .unwrap();

    let denied_context =
        FilterContext::default().with_auth_value("id", FilterValue::String("user_2".to_string()));
    let denied = store
        .update_record_with_context("posts", "post_1", json!({"title": "Nope"}), denied_context)
        .unwrap_err();
    assert!(denied.to_string().contains("update rule denied"));

    let allowed_context =
        FilterContext::default().with_auth_value("id", FilterValue::String("user_1".to_string()));
    let updated = store
        .update_record_with_context(
            "posts",
            "post_1",
            json!({"title": "Still mine"}),
            allowed_context.clone(),
        )
        .unwrap();
    assert_eq!(updated["title"], "Still mine");

    let denied_context =
        FilterContext::default().with_auth_value("id", FilterValue::String("user_2".to_string()));
    let denied = store
        .delete_record_with_context("posts", "post_1", denied_context)
        .unwrap_err();
    assert!(denied.to_string().contains("delete rule denied"));

    store
        .delete_record_with_context("posts", "post_1", allowed_context)
        .unwrap();
    let list = store.list_records("posts", ListOptions::default()).unwrap();
    assert_eq!(list.total_items, 0);
}

#[test]
fn applies_request_changed_modifier_in_update_rules() {
    let store = Store::open_in_memory().unwrap();
    store
        .create_collection(
            CollectionConfig::new(
                "posts",
                [
                    CollectionField::new("title", CollectionFieldKind::Text),
                    CollectionField::new("owner", CollectionFieldKind::Text),
                    CollectionField::new("role", CollectionFieldKind::Text),
                ],
            )
            .with_update_rule("owner = @request.auth.id && @request.body.role:changed = false"),
        )
        .unwrap();
    store
        .create_record(
            "posts",
            json!({"id": "post_1", "title": "Mine", "owner": "user_1", "role": "member"}),
        )
        .unwrap();

    let context =
        FilterContext::default().with_auth_value("id", FilterValue::String("user_1".to_string()));
    let title_update = store
        .update_record_with_context(
            "posts",
            "post_1",
            json!({"title": "Renamed"}),
            context.clone(),
        )
        .unwrap();
    assert_eq!(title_update["title"], "Renamed");

    let same_role = store
        .update_record_with_context(
            "posts",
            "post_1",
            json!({"role": "member"}),
            context.clone(),
        )
        .unwrap();
    assert_eq!(same_role["role"], "member");

    let changed_role = store
        .update_record_with_context("posts", "post_1", json!({"role": "admin"}), context)
        .unwrap_err();
    assert!(changed_role.to_string().contains("update rule denied"));
}

#[test]
fn applies_each_field_modifier_in_list_rules() {
    let store = Store::open_in_memory().unwrap();
    store
        .create_collection(
            CollectionConfig::new(
                "posts",
                [
                    CollectionField::new("title", CollectionFieldKind::Text),
                    CollectionField::new("scopes", CollectionFieldKind::Array),
                ],
            )
            .with_list_rule("scopes:each ~ 'create'"),
        )
        .unwrap();
    store
        .create_record(
            "posts",
            json!({"title": "Allowed", "scopes": ["post:create", "comment:create"]}),
        )
        .unwrap();
    store
        .create_record(
            "posts",
            json!({"title": "Denied", "scopes": ["post:create", "post:delete"]}),
        )
        .unwrap();

    let list = store.list_records("posts", ListOptions::default()).unwrap();
    assert_eq!(list.total_items, 1);
    assert_eq!(list.items[0]["title"], "Allowed");
}

#[test]
fn handles_pocketbase_style_records_http_routes() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let collection_response = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "title", "kind": "text"},
                    {"name": "published", "kind": "bool"},
                    {"name": "owner", "kind": "text"},
                    {"name": "score", "kind": "number"}
                ],
                "listRule": "owner = @request.auth.id"
            }),
        )
        .unwrap(),
    );
    assert_eq!(collection_response.status, 200);

    let first = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Rusty Base", "published": true, "owner": "user_1", "score": 10}),
        )
        .unwrap(),
    );
    assert_eq!(first.status, 200);

    let second = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Hidden", "published": true, "owner": "user_2", "score": 12}),
        )
        .unwrap(),
    );
    assert_eq!(second.status, 200);

    let list = app.handle(
        HttpRequest::new(
            "GET",
            "/api/collections/posts/records?filter=published%20%3D%20true",
        )
        .with_header("X-RB-Auth-ID", "user_1"),
    );

    assert_eq!(list.status, 200);
    assert_eq!(list.body["totalItems"], 1);
    assert_eq!(list.body["items"][0]["title"], "Rusty Base");

    let third = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Lower Score", "published": true, "owner": "user_1", "score": 3}),
        )
        .unwrap(),
    );
    assert_eq!(third.status, 200);

    let sorted_desc = app.handle(
        HttpRequest::new(
            "GET",
            "/api/collections/posts/records?filter=published%20%3D%20true&sort=-score",
        )
        .with_header("X-RB-Auth-ID", "user_1"),
    );

    assert_eq!(sorted_desc.status, 200);
    assert_eq!(sorted_desc.body["totalItems"], 2);
    assert_eq!(sorted_desc.body["items"][0]["title"], "Rusty Base");
    assert_eq!(sorted_desc.body["items"][1]["title"], "Lower Score");

    let sorted_asc = app.handle(
        HttpRequest::new(
            "GET",
            "/api/collections/posts/records?filter=published%20%3D%20true&sort=score",
        )
        .with_header("X-RB-Auth-ID", "user_1"),
    );

    assert_eq!(sorted_asc.status, 200);
    assert_eq!(sorted_asc.body["items"][0]["title"], "Lower Score");
    assert_eq!(sorted_asc.body["items"][1]["title"], "Rusty Base");

    let skipped_total = app.handle(
        HttpRequest::new(
            "GET",
            "/api/collections/posts/records?filter=published%20%3D%20true&sort=score&skipTotal=true",
        )
        .with_header("X-RB-Auth-ID", "user_1"),
    );

    assert_eq!(skipped_total.status, 200);
    assert_eq!(skipped_total.body["totalItems"], -1);
    assert_eq!(skipped_total.body["totalPages"], -1);
    assert_eq!(skipped_total.body["items"].as_array().unwrap().len(), 2);

    let invalid_sort = app.handle(
        HttpRequest::new("GET", "/api/collections/posts/records?sort=title%3Bdrop")
            .with_header("X-RB-Auth-ID", "user_1"),
    );
    assert_eq!(invalid_sort.status, 400);
}

#[test]
fn handles_json_record_batch_requests_transactionally() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let collection_response = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "title", "kind": "text"},
                    {"name": "published", "kind": "bool"}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(collection_response.status, 200);

    let batch = app.handle(
        HttpRequest::json(
            "POST",
            "/api/batch",
            json!({
                "requests": [
                    {
                        "method": "POST",
                        "url": "/api/collections/posts/records",
                        "body": {"id": "post_1", "title": "One", "published": true}
                    },
                    {
                        "method": "PUT",
                        "url": "/api/collections/posts/records",
                        "body": {"id": "post_2", "title": "Two", "published": false}
                    },
                    {
                        "method": "PATCH",
                        "url": "/api/collections/posts/records/post_1",
                        "body": {"title": "One Updated"}
                    },
                    {
                        "method": "DELETE",
                        "url": "/api/collections/posts/records/post_2"
                    }
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(batch.status, 200);
    assert_eq!(batch.body.as_array().unwrap().len(), 4);
    assert_eq!(batch.body[0]["status"], 200);
    assert_eq!(batch.body[1]["status"], 200);
    assert_eq!(batch.body[2]["status"], 200);
    assert_eq!(batch.body[3]["status"], 204);
    assert_eq!(batch.body[2]["body"]["title"], "One Updated");

    let updated = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts/records/post_1",
    ));
    assert_eq!(updated.status, 200);
    assert_eq!(updated.body["title"], "One Updated");

    let deleted = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts/records/post_2",
    ));
    assert_eq!(deleted.status, 404);

    let failed = app.handle(
        HttpRequest::json(
            "POST",
            "/api/batch",
            json!({
                "requests": [
                    {
                        "method": "POST",
                        "url": "/api/collections/posts/records",
                        "body": {"id": "post_rollback", "title": "Rollback", "published": true}
                    },
                    {
                        "method": "PATCH",
                        "url": "/api/collections/posts/records/missing",
                        "body": {"title": "Missing"}
                    }
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(failed.status, 400);
    assert_eq!(failed.body["message"], "Batch transaction failed.");
    assert_eq!(
        failed.body["data"]["requests"]["1"]["code"],
        "batch_request_failed"
    );
    assert_eq!(
        failed.body["data"]["requests"]["1"]["response"]["status"],
        404
    );

    let rolled_back = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts/records/post_rollback",
    ));
    assert_eq!(rolled_back.status, 404);

    let custom_auth = app.handle(
        HttpRequest::json(
            "POST",
            "/api/batch",
            json!({
                "requests": [
                    {
                        "method": "POST",
                        "url": "/api/collections/posts/records",
                        "headers": {"Authorization": "Bearer child_token"},
                        "body": {"id": "post_custom_auth", "title": "Custom Auth"}
                    }
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(custom_auth.status, 400);
    assert_eq!(
        custom_auth.body["data"]["requests"]["0"]["response"]["status"],
        400
    );
}

#[test]
fn publishes_realtime_record_events() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let connect_response = app.handle(HttpRequest::new("GET", "/api/realtime"));
    assert_eq!(connect_response.status, 200);
    assert_eq!(connect_response.content_type, "text/event-stream");
    let connect_body = String::from_utf8(connect_response.raw_body).unwrap();
    assert!(connect_body.contains("event: PB_CONNECT"));
    assert!(connect_body.contains("clientId"));

    let collection = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "title", "kind": "text"},
                    {"name": "public", "kind": "bool"}
                ],
                "listRule": "public = true"
            }),
        )
        .unwrap(),
    );
    assert_eq!(collection.status, 200);

    let connection = app.realtime_connect().unwrap();
    let connect = expect_realtime_event(&connection);
    assert_eq!(connect.event, "PB_CONNECT");
    assert_eq!(connect.data["clientId"], connection.client_id);

    let invalid_client = app.handle(
        HttpRequest::json(
            "POST",
            "/api/realtime",
            json!({"clientId": "missing", "subscriptions": ["posts/*"]}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_client.status, 404);

    let subscribe = app.handle(
        HttpRequest::json(
            "POST",
            "/api/realtime",
            json!({"clientId": connection.client_id, "subscriptions": ["posts/*"]}),
        )
        .unwrap(),
    );
    assert_eq!(subscribe.status, 204);

    let visible = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"id": "post_1", "title": "Visible", "public": true}),
        )
        .unwrap(),
    );
    assert_eq!(visible.status, 200);
    let event = expect_realtime_event(&connection);
    assert_eq!(event.event, "posts/*");
    assert_eq!(event.data["action"], "create");
    assert_eq!(event.data["record"]["id"], "post_1");

    let hidden = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"id": "post_2", "title": "Hidden", "public": false}),
        )
        .unwrap(),
    );
    assert_eq!(hidden.status, 200);
    assert!(connection.recv_timeout(Duration::from_millis(50)).is_err());

    let updated = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_1",
            json!({"title": "Updated"}),
        )
        .unwrap(),
    );
    assert_eq!(updated.status, 200);
    let event = expect_realtime_event(&connection);
    assert_eq!(event.data["action"], "update");
    assert_eq!(event.data["record"]["title"], "Updated");

    let deleted = app.handle(HttpRequest::new(
        "DELETE",
        "/api/collections/posts/records/post_1",
    ));
    assert_eq!(deleted.status, 204);
    let event = expect_realtime_event(&connection);
    assert_eq!(event.data["action"], "delete");
    assert_eq!(event.data["record"]["id"], "post_1");
}

#[test]
fn uploads_and_serves_file_fields() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let collection_response = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "docs",
                "fields": [
                    {"name": "title", "kind": "text"},
                    {"name": "public", "kind": "bool"},
                    {"name": "attachment", "type": "file", "maxSelect": 1},
                    {"name": "documents", "type": "file", "maxSelect": 3}
                ],
                "viewRule": "public = true"
            }),
        )
        .unwrap(),
    );
    assert_eq!(collection_response.status, 200);

    let created = app.handle(multipart_request(
        "POST",
        "/api/collections/docs/records",
        "rb-boundary",
        vec![
            multipart_field("id", "doc_1"),
            multipart_field("title", "Rusty files"),
            multipart_field("public", "true"),
            multipart_file("attachment", "hello.txt", "text/plain", b"hello file"),
            multipart_file("documents", "one.txt", "text/plain", b"one"),
            multipart_file("documents", "two.txt", "text/plain", b"two"),
        ],
    ));
    assert_eq!(created.status, 200);
    assert_eq!(created.body["id"], "doc_1");
    assert_eq!(created.body["title"], "Rusty files");
    let attachment = created.body["attachment"].as_str().unwrap().to_string();
    assert!(attachment.starts_with("hello_"));
    assert!(attachment.ends_with(".txt"));
    let created_documents = created.body["documents"].as_array().unwrap();
    assert_eq!(created_documents.len(), 2);
    let first_document = created_documents[0].as_str().unwrap().to_string();
    let second_document = created_documents[1].as_str().unwrap().to_string();

    let file = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/docs/doc_1/{attachment}"),
    ));
    assert_eq!(file.status, 200);
    assert_eq!(file.content_type, "text/plain");
    assert_eq!(file.raw_body, b"hello file");

    let replaced = app.handle(multipart_request(
        "PATCH",
        "/api/collections/docs/records/doc_1",
        "rb-boundary-2",
        vec![multipart_file(
            "attachment",
            "updated.md",
            "text/markdown",
            b"# updated",
        )],
    ));
    assert_eq!(replaced.status, 200);
    let updated_attachment = replaced.body["attachment"].as_str().unwrap().to_string();
    assert_ne!(updated_attachment, attachment);
    assert!(updated_attachment.starts_with("updated_"));
    assert_eq!(replaced.body["documents"].as_array().unwrap().len(), 2);

    let old_file = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/docs/doc_1/{attachment}"),
    ));
    assert_eq!(old_file.status, 404);

    let updated_file = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/docs/doc_1/{updated_attachment}"),
    ));
    assert_eq!(updated_file.status, 200);
    assert_eq!(updated_file.content_type, "text/markdown");
    assert_eq!(updated_file.raw_body, b"# updated");

    let downloaded_file = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/docs/doc_1/{updated_attachment}?thumb=100x100&download=1"),
    ));
    assert_eq!(downloaded_file.status, 200);
    assert_eq!(downloaded_file.raw_body, b"# updated");
    assert_eq!(
        downloaded_file.headers["content-disposition"],
        format!("attachment; filename=\"{updated_attachment}\"")
    );
    let downloaded_http = String::from_utf8(downloaded_file.to_http_bytes()).unwrap();
    assert!(downloaded_http.contains(&format!(
        "content-disposition: attachment; filename=\"{updated_attachment}\""
    )));

    let appended = app.handle(multipart_request(
        "PATCH",
        "/api/collections/docs/records/doc_1",
        "rb-boundary-3",
        vec![multipart_file(
            "documents+",
            "three.txt",
            "text/plain",
            b"three",
        )],
    ));
    assert_eq!(appended.status, 200);
    let appended_documents = appended.body["documents"].as_array().unwrap();
    assert_eq!(appended_documents.len(), 3);
    assert_eq!(appended_documents[0], first_document);
    assert_eq!(appended_documents[1], second_document);
    let third_document = appended_documents[2].as_str().unwrap().to_string();
    assert!(third_document.starts_with("three_"));

    let removed = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/docs/records/doc_1",
            json!({"documents-": [second_document.clone()]}),
        )
        .unwrap(),
    );
    assert_eq!(removed.status, 200);
    let removed_documents = removed.body["documents"].as_array().unwrap();
    assert_eq!(removed_documents.len(), 2);
    assert_eq!(removed_documents[0], first_document);
    assert_eq!(removed_documents[1], third_document);

    let removed_file = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/docs/doc_1/{second_document}"),
    ));
    assert_eq!(removed_file.status, 404);

    let prepended = app.handle(multipart_request(
        "PATCH",
        "/api/collections/docs/records/doc_1",
        "rb-boundary-4",
        vec![multipart_file(
            "+documents",
            "zero.txt",
            "text/plain",
            b"zero",
        )],
    ));
    assert_eq!(prepended.status, 200);
    let prepended_documents = prepended.body["documents"].as_array().unwrap();
    assert_eq!(prepended_documents.len(), 3);
    let zero_document = prepended_documents[0].as_str().unwrap().to_string();
    assert!(zero_document.starts_with("zero_"));
    assert_eq!(prepended_documents[1], first_document);
    assert_eq!(prepended_documents[2], third_document);

    let cleared = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/docs/records/doc_1",
            json!({"documents": []}),
        )
        .unwrap(),
    );
    assert_eq!(cleared.status, 200);
    assert_eq!(cleared.body["documents"], json!([]));

    let cleared_file = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/docs/doc_1/{zero_document}"),
    ));
    assert_eq!(cleared_file.status, 404);

    let private = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/docs/records/doc_1",
            json!({"public": false}),
        )
        .unwrap(),
    );
    assert_eq!(private.status, 200);

    let still_public = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/docs/doc_1/{updated_attachment}"),
    ));
    assert_eq!(still_public.status, 200);
    assert_eq!(still_public.raw_body, b"# updated");
}

#[test]
fn generates_image_file_thumbnails() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let collection_response = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "images",
                "fields": [
                    {"name": "public", "kind": "bool"},
                    {
                        "name": "photo",
                        "type": "file",
                        "maxSelect": 1,
                        "maxSize": 4096,
                        "mimeTypes": ["image/png"],
                        "thumbs": ["2x0", "0x1", "2x2f", "1x1t"]
                    }
                ],
                "viewRule": "public = true"
            }),
        )
        .unwrap(),
    );
    assert_eq!(collection_response.status, 200);
    let photo_field = collection_field(&collection_response.body, "photo");
    assert_eq!(photo_field["maxSize"], 4096);
    assert_eq!(photo_field["mimeTypes"], json!(["image/png"]));
    assert_eq!(photo_field["thumbs"], json!(["2x0", "0x1", "2x2f", "1x1t"]));

    let image = png_fixture(4, 2);
    let created = app.handle(multipart_request(
        "POST",
        "/api/collections/images/records",
        "rb-image-boundary",
        vec![
            multipart_field("id", "image_1"),
            multipart_field("public", "true"),
            multipart_file_bytes("photo", "photo.png", "image/png", image.clone()),
        ],
    ));
    assert_eq!(created.status, 200);
    let photo = created.body["photo"].as_str().unwrap().to_string();

    let original = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/images/image_1/{photo}"),
    ));
    assert_eq!(original.status, 200);
    assert_eq!(original.content_type, "image/png");
    assert_eq!(original.raw_body, image);

    let proportional = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/images/image_1/{photo}?thumb=2x0"),
    ));
    assert_eq!(proportional.status, 200);
    assert_eq!(proportional.content_type, "image/png");
    assert_eq!(image_dimensions(&proportional.raw_body), (2, 1));

    let height_only = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/images/image_1/{photo}?thumb=0x1"),
    ));
    assert_eq!(height_only.status, 200);
    assert_eq!(image_dimensions(&height_only.raw_body), (2, 1));

    let fitted = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/images/image_1/{photo}?thumb=2x2f"),
    ));
    assert_eq!(fitted.status, 200);
    assert_eq!(image_dimensions(&fitted.raw_body), (2, 1));

    let cropped = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/images/image_1/{photo}?thumb=1x1t"),
    ));
    assert_eq!(cropped.status, 200);
    assert_eq!(cropped.content_type, "image/png");
    assert_eq!(image_dimensions(&cropped.raw_body), (1, 1));
    assert_ne!(cropped.raw_body, original.raw_body);

    let invalid_thumb = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/images/image_1/{photo}?thumb=bad"),
    ));
    assert_eq!(invalid_thumb.status, 200);
    assert_eq!(invalid_thumb.raw_body, original.raw_body);

    let unconfigured_thumb = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/images/image_1/{photo}?thumb=3x0"),
    ));
    assert_eq!(unconfigured_thumb.status, 200);
    assert_eq!(unconfigured_thumb.raw_body, original.raw_body);
}

#[test]
fn validates_file_field_upload_options() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let collection = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "uploads",
                "fields": [{
                    "name": "asset",
                    "type": "file",
                    "maxSize": 4,
                    "mimeTypes": ["text/plain"]
                }]
            }),
        )
        .unwrap(),
    );
    assert_eq!(collection.status, 200);

    let too_large = app.handle(multipart_request(
        "POST",
        "/api/collections/uploads/records",
        "rb-large-file-boundary",
        vec![multipart_file("asset", "large.txt", "text/plain", b"large")],
    ));
    assert_eq!(too_large.status, 400);
    assert_eq!(
        too_large.body["data"]["asset"]["code"],
        "validation_max_size"
    );

    let wrong_type = app.handle(multipart_request(
        "POST",
        "/api/collections/uploads/records",
        "rb-mime-file-boundary",
        vec![multipart_file(
            "asset",
            "asset.bin",
            "application/octet-stream",
            b"ok",
        )],
    ));
    assert_eq!(wrong_type.status, 400);
    assert_eq!(
        wrong_type.body["data"]["asset"]["code"],
        "validation_mime_type"
    );

    let accepted = app.handle(multipart_request(
        "POST",
        "/api/collections/uploads/records",
        "rb-good-file-boundary",
        vec![multipart_file(
            "asset",
            "ok.txt",
            "text/plain; charset=utf-8",
            b"ok",
        )],
    ));
    assert_eq!(accepted.status, 200);
    assert!(accepted.body["asset"].as_str().unwrap().starts_with("ok_"));
}

#[test]
fn generates_file_tokens_for_protected_file_access() {
    let path = temp_db_path("protected-file-token-expiry");
    let app = RustyBaseApp::new(Store::open(&path).unwrap());

    let users = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "users",
                "type": "auth",
                "fields": [{"name": "email", "type": "email"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(users.status, 200);

    for (id, email) in [
        ("user_1", "owner@example.com"),
        ("user_2", "other@example.com"),
    ] {
        let created = app.handle(
            HttpRequest::json(
                "POST",
                "/api/collections/users/records",
                json!({
                    "id": id,
                    "email": email,
                    "password": "correct horse",
                    "passwordConfirm": "correct horse"
                }),
            )
            .unwrap(),
        );
        assert_eq!(created.status, 200);
    }

    let docs = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "docs",
                "fields": [
                    {"name": "owner", "kind": "text"},
                    {"name": "contract", "type": "file", "protected": true}
                ],
                "viewRule": "owner = @request.auth.id"
            }),
        )
        .unwrap(),
    );
    assert_eq!(docs.status, 200);
    assert_eq!(collection_field(&docs.body, "contract")["protected"], true);

    let created = app.handle(multipart_request(
        "POST",
        "/api/collections/docs/records",
        "rb-protected-boundary",
        vec![
            multipart_field("id", "doc_1"),
            multipart_field("owner", "user_1"),
            multipart_file(
                "contract",
                "contract.pdf",
                "application/pdf",
                b"contract bytes",
            ),
        ],
    ));
    assert_eq!(created.status, 200);
    let contract = created.body["contract"].as_str().unwrap().to_string();

    let without_token = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/docs/doc_1/{contract}"),
    ));
    assert_eq!(without_token.status, 404);

    let missing_auth = app.handle(HttpRequest::new("POST", "/api/files/token"));
    assert_eq!(missing_auth.status, 403);

    let owner_login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "owner@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(owner_login.status, 200);
    let owner_auth_token = owner_login.body["token"].as_str().unwrap();

    let owner_file_token_response = app.handle(
        HttpRequest::new("POST", "/api/files/token").with_header("Authorization", owner_auth_token),
    );
    assert_eq!(owner_file_token_response.status, 200);
    let owner_file_token = owner_file_token_response.body["token"]
        .as_str()
        .unwrap()
        .to_string();

    let allowed = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/docs/doc_1/{contract}?token={owner_file_token}"),
    ));
    assert_eq!(allowed.status, 200);
    assert_eq!(allowed.content_type, "application/pdf");
    assert_eq!(allowed.raw_body, b"contract bytes");

    {
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            r#"UPDATE "_rb_file_tokens" SET expires = ?1 WHERE token = ?2"#,
            params!["0", &owner_file_token],
        )
        .unwrap();
    }
    let expired = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/docs/doc_1/{contract}?token={owner_file_token}"),
    ));
    assert_eq!(expired.status, 403);
    assert!(expired.body["message"]
        .as_str()
        .unwrap()
        .contains("expired file token"));

    let other_login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "other@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(other_login.status, 200);
    let other_auth_token = other_login.body["token"].as_str().unwrap();
    let other_file_token_response = app.handle(
        HttpRequest::new("POST", "/api/files/token")
            .with_header("Authorization", format!("Bearer {other_auth_token}")),
    );
    assert_eq!(other_file_token_response.status, 200);
    let other_file_token = other_file_token_response.body["token"].as_str().unwrap();

    let denied = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/docs/doc_1/{contract}?token={other_file_token}"),
    ));
    assert_eq!(denied.status, 404);
    drop(app);
    fs::remove_file(path).ok();
}

#[test]
fn updates_collections_and_renames_record_tables() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let collection_response = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [{"name": "title", "kind": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(collection_response.status, 200);
    let title_field = collection_field(&collection_response.body, "title");
    assert_eq!(title_field["type"], "text");
    assert!(title_field.get("kind").is_none());
    let title_field_id = title_field["id"].as_str().unwrap().to_string();

    let created = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Rusty Base"}),
        )
        .unwrap(),
    );
    assert_eq!(created.status, 200);

    let view = app.handle(HttpRequest::new("GET", "/api/collections/posts"));
    assert_eq!(view.status, 200);
    assert_eq!(view.body["name"], "posts");

    let patched = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts",
            json!({
                "name": "articles",
                "fields": [
                    {"name": "title", "kind": "text"},
                    {"name": "tags", "kind": "array"}
                ],
                "indexes": [
                    " CREATE INDEX idx_articles_title ON articles (title) ",
                    "CREATE INDEX idx_articles_title ON articles (title)"
                ],
                "listRule": "title ~ 'Rusty'"
            }),
        )
        .unwrap(),
    );
    assert_eq!(patched.status, 200);
    assert_eq!(patched.body["name"], "articles");
    assert_eq!(user_collection_fields(&patched.body).len(), 2);
    let patched_title = collection_field(&patched.body, "title");
    assert_eq!(patched_title["id"], title_field_id);
    assert_eq!(patched_title["type"], "text");
    assert_eq!(
        patched.body["indexes"],
        json!(["CREATE INDEX idx_articles_title ON articles (title)"])
    );
    assert!(collection_field(&patched.body, "tags")["id"]
        .as_str()
        .unwrap()
        .starts_with("array"));

    let old_collection = app.handle(HttpRequest::new("GET", "/api/collections/posts"));
    assert_eq!(old_collection.status, 404);

    let old_records = app.handle(HttpRequest::new("GET", "/api/collections/posts/records"));
    assert_eq!(old_records.status, 404);

    let list = app.handle(HttpRequest::new("GET", "/api/collections/articles/records"));
    assert_eq!(list.status, 200);
    assert_eq!(list.body["totalItems"], 1);
    assert_eq!(list.body["items"][0]["collectionName"], "articles");
    assert_eq!(list.body["items"][0]["title"], "Rusty Base");

    let created_with_new_field = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/articles/records",
            json!({"title": "Rusty Addendum", "tags": ["rust"]}),
        )
        .unwrap(),
    );
    assert_eq!(created_with_new_field.status, 200);
    assert_eq!(created_with_new_field.body["tags"], json!(["rust"]));
}

#[test]
fn manages_collections_by_id_and_projects_collection_responses() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let created = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections?fields=id,name,type",
            json!({
                "id": "posts_collection",
                "name": "posts",
                "fields": [{"name": "title", "kind": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(created.status, 200);
    assert_eq!(created.body["id"], "posts_collection");
    assert_eq!(created.body["name"], "posts");
    assert_eq!(created.body["type"], "base");
    assert!(created.body.get("fields").is_none());

    let by_id = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts_collection?fields=id,name,system",
    ));
    assert_eq!(by_id.status, 200);
    assert_eq!(by_id.body["id"], "posts_collection");
    assert_eq!(by_id.body["name"], "posts");
    assert_eq!(by_id.body["system"], false);
    assert!(by_id.body.get("type").is_none());

    let list_by_id_filter = app.handle(HttpRequest::new(
        "GET",
        "/api/collections?filter=id%3D%22posts_collection%22",
    ));
    assert_eq!(list_by_id_filter.status, 200);
    assert_eq!(list_by_id_filter.body["totalItems"], 1);
    assert_eq!(list_by_id_filter.body["items"][0]["name"], "posts");

    let patched = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts_collection?fields=id,name",
            json!({"name": "articles"}),
        )
        .unwrap(),
    );
    assert_eq!(patched.status, 200);
    assert_eq!(patched.body["id"], "posts_collection");
    assert_eq!(patched.body["name"], "articles");
    assert!(patched.body.get("fields").is_none());

    let old_name = app.handle(HttpRequest::new("GET", "/api/collections/posts"));
    assert_eq!(old_name.status, 404);

    let by_id_after_rename = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts_collection?fields=id,name",
    ));
    assert_eq!(by_id_after_rename.status, 200);
    assert_eq!(by_id_after_rename.body["name"], "articles");

    let record = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts_collection/records",
            json!({"id": "post_1", "title": "Keep metadata sharp"}),
        )
        .unwrap(),
    );
    assert_eq!(record.status, 200);
    assert_eq!(record.body["collectionId"], "posts_collection");
    assert_eq!(record.body["collectionName"], "articles");

    let record_by_collection_id = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts_collection/records/post_1",
    ));
    assert_eq!(record_by_collection_id.status, 200);
    assert_eq!(
        record_by_collection_id.body["collectionId"],
        "posts_collection"
    );
    assert_eq!(record_by_collection_id.body["collectionName"], "articles");
    assert_eq!(record_by_collection_id.body["title"], "Keep metadata sharp");

    let updated_by_collection_id = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts_collection/records/post_1",
            json!({"title": "Still sharp"}),
        )
        .unwrap(),
    );
    assert_eq!(updated_by_collection_id.status, 200);
    assert_eq!(
        updated_by_collection_id.body["collectionId"],
        "posts_collection"
    );
    assert_eq!(updated_by_collection_id.body["title"], "Still sharp");

    let list_by_collection_id = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts_collection/records",
    ));
    assert_eq!(list_by_collection_id.status, 200);
    assert_eq!(list_by_collection_id.body["totalItems"], 1);
    assert_eq!(
        list_by_collection_id.body["items"][0]["collectionId"],
        "posts_collection"
    );

    let truncated = app.handle(HttpRequest::new(
        "DELETE",
        "/api/collections/posts_collection/truncate",
    ));
    assert_eq!(truncated.status, 204);

    let empty = app.handle(HttpRequest::new("GET", "/api/collections/articles/records"));
    assert_eq!(empty.status, 200);
    assert_eq!(empty.body["totalItems"], 0);

    let deleted = app.handle(HttpRequest::new(
        "DELETE",
        "/api/collections/posts_collection",
    ));
    assert_eq!(deleted.status, 204);

    let gone = app.handle(HttpRequest::new("GET", "/api/collections/posts_collection"));
    assert_eq!(gone.status, 404);
}

#[test]
fn persists_pocketbase_style_field_options() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let created = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {
                        "id": "title_field",
                        "name": "title",
                        "type": "text",
                        "required": true,
                        "hidden": true,
                        "presentable": true,
                        "primaryKey": false,
                        "min": 3,
                        "max": 80,
                        "pattern": "^[A-Z].+",
                        "autogeneratePattern": "[A-Z]{4}"
                    },
                    {
                        "name": "score",
                        "type": "number",
                        "min": 1,
                        "max": 10
                    },
                    {
                        "name": "status",
                        "type": "select",
                        "values": ["draft", "published"]
                    },
                    {
                        "name": "metadata",
                        "type": "json",
                        "maxSize": 128
                    },
                    {
                        "name": "published",
                        "kind": "bool",
                        "required": true
                    }
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(created.status, 200);
    let title_field = collection_field(&created.body, "title");
    assert_eq!(title_field["id"], "title_field");
    assert_eq!(title_field["type"], "text");
    assert_eq!(title_field["required"], true);
    assert_eq!(title_field["hidden"], true);
    assert_eq!(title_field["presentable"], true);
    assert_eq!(title_field["primaryKey"], false);
    assert_eq!(title_field["min"], 3);
    assert_eq!(title_field["max"], 80);
    assert_eq!(title_field["pattern"], "^[A-Z].+");
    assert_eq!(title_field["autogeneratePattern"], "[A-Z]{4}");
    assert!(title_field.get("kind").is_none());
    let score_field = collection_field(&created.body, "score");
    assert_eq!(score_field["type"], "number");
    assert_eq!(score_field["min"], 1);
    assert_eq!(score_field["max"], 10);
    let status_field = collection_field(&created.body, "status");
    assert_eq!(status_field["type"], "select");
    assert_eq!(status_field["values"], json!(["draft", "published"]));
    let metadata_field = collection_field(&created.body, "metadata");
    assert_eq!(metadata_field["type"], "json");
    assert_eq!(metadata_field["maxSize"], 128);
    let published_field = collection_field(&created.body, "published");
    assert_eq!(published_field["required"], true);
    assert!(published_field.get("min").is_none());

    let patched = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts",
            json!({
                "fields": [
                    {
                        "name": "title",
                        "type": "text",
                        "required": true,
                        "min": 5,
                        "max": 100
                    }
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(patched.status, 200);
    let patched_title = collection_field(&patched.body, "title");
    assert_eq!(patched_title["id"], "title_field");
    assert_eq!(patched_title["min"], 5);
    assert_eq!(patched_title["max"], 100);
    assert_eq!(patched_title["pattern"], "");
    assert_eq!(patched_title["autogeneratePattern"], "");

    let invalid_range = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "bad_ranges",
                "fields": [{"name": "title", "type": "text", "min": 10, "max": 2}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(invalid_range.status, 400);

    let invalid_number_range = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "bad_number_ranges",
                "fields": [{"name": "score", "type": "number", "min": 10, "max": 2}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(invalid_number_range.status, 400);

    let invalid_min_kind = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "bad_min_kind",
                "fields": [{"name": "published", "type": "bool", "min": 1}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(invalid_min_kind.status, 400);

    let invalid_select_values = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "bad_select_values",
                "fields": [{"name": "status", "type": "select", "values": []}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(invalid_select_values.status, 400);

    let invalid_select_values_kind = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "bad_select_values_kind",
                "fields": [{"name": "title", "type": "text", "values": ["draft"]}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(invalid_select_values_kind.status, 400);

    let invalid_max_size_kind = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "bad_max_size_kind",
                "fields": [{"name": "title", "type": "text", "maxSize": 10}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(invalid_max_size_kind.status, 400);

    let invalid_kind = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "bad_kind",
                "fields": [{"name": "published", "type": "bool", "pattern": "yes"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(invalid_kind.status, 400);
}

#[test]
fn supports_url_editor_and_date_field_parity() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let created = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "pages",
                "fields": [
                    {
                        "name": "site",
                        "type": "url",
                        "required": true,
                        "onlyDomains": ["example.com"],
                        "exceptDomains": ["blocked.example.com"]
                    },
                    {
                        "name": "body",
                        "type": "editor",
                        "maxSize": 16
                    },
                    {
                        "name": "publishedAt",
                        "type": "datetime"
                    }
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(created.status, 200);
    let site_field = collection_field(&created.body, "site");
    assert_eq!(site_field["type"], "url");
    assert_eq!(site_field["onlyDomains"], json!(["example.com"]));
    assert_eq!(site_field["exceptDomains"], json!(["blocked.example.com"]));
    let body_field = collection_field(&created.body, "body");
    assert_eq!(body_field["type"], "editor");
    assert_eq!(body_field["maxSize"], 16);
    assert_eq!(
        collection_field(&created.body, "publishedAt")["type"],
        "date"
    );

    let valid = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/pages/records",
            json!({
                "id": "page_1",
                "site": "https://docs.example.com/guide?ref=rusty",
                "body": "<p>hi</p>",
                "publishedAt": "2024-11-10 18:45:27.123Z"
            }),
        )
        .unwrap(),
    );
    assert_eq!(valid.status, 200);

    let invalid_url = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/pages/records",
            json!({"site": "example.com"}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_url.status, 400);
    assert_eq!(
        invalid_url.body["data"]["site"]["code"],
        "validation_is_url"
    );

    let blocked_domain = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/pages/records",
            json!({"site": "https://blocked.example.com"}),
        )
        .unwrap(),
    );
    assert_eq!(blocked_domain.status, 400);
    assert_eq!(
        blocked_domain.body["data"]["site"]["code"],
        "validation_domain_constraint"
    );

    let too_large_editor = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/pages/records",
            json!({
                "site": "https://example.com",
                "body": "<p>too long body</p>"
            }),
        )
        .unwrap(),
    );
    assert_eq!(too_large_editor.status, 400);
    assert_eq!(
        too_large_editor.body["data"]["body"]["code"],
        "validation_max_size"
    );

    let invalid_domain_options = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "bad_domains",
                "fields": [{"name": "published", "type": "bool", "onlyDomains": ["example.com"]}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(invalid_domain_options.status, 400);
}

#[test]
fn supports_autodate_field_metadata_and_record_stamping() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let created_collection = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "events",
                "fields": [
                    {"name": "title", "type": "text"},
                    {"name": "startedAt", "type": "autodate", "onCreate": true},
                    {
                        "name": "touchedAt",
                        "type": "autodate",
                        "onCreate": true,
                        "onUpdate": true
                    }
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(created_collection.status, 200);
    assert_eq!(
        collection_field(&created_collection.body, "id")["type"],
        "text"
    );
    assert_eq!(
        collection_field(&created_collection.body, "created")["type"],
        "autodate"
    );
    assert_eq!(
        collection_field(&created_collection.body, "created")["onCreate"],
        true
    );
    assert_eq!(
        collection_field(&created_collection.body, "created")["onUpdate"],
        false
    );
    assert_eq!(
        collection_field(&created_collection.body, "updated")["type"],
        "autodate"
    );
    assert_eq!(
        collection_field(&created_collection.body, "updated")["onUpdate"],
        true
    );
    assert_eq!(
        collection_field(&created_collection.body, "startedAt")["type"],
        "autodate"
    );
    assert_eq!(
        collection_field(&created_collection.body, "startedAt")["onCreate"],
        true
    );

    let created_record = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/events/records",
            json!({"id": "event_1", "title": "Launch"}),
        )
        .unwrap(),
    );
    assert_eq!(created_record.status, 200);
    assert_pocketbase_datetime_value(&created_record.body["startedAt"]);
    assert_pocketbase_datetime_value(&created_record.body["touchedAt"]);

    let echoed_patch = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/events",
            json!({"fields": created_collection.body["fields"].clone()}),
        )
        .unwrap(),
    );
    assert_eq!(echoed_patch.status, 200);
    assert_eq!(user_collection_fields(&echoed_patch.body).len(), 3);
    assert_eq!(
        collection_field(&echoed_patch.body, "created")["type"],
        "autodate"
    );

    let reserved_user_field = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "bad_reserved",
                "fields": [{"name": "id", "type": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(reserved_user_field.status, 400);

    let updated_record = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/events/records/event_1",
            json!({"title": "Launch day"}),
        )
        .unwrap(),
    );
    assert_eq!(updated_record.status, 200);
    assert_pocketbase_datetime_value(&updated_record.body["startedAt"]);
    assert_pocketbase_datetime_value(&updated_record.body["touchedAt"]);
}

#[test]
fn supports_geo_point_field_values_and_filters() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let created = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "places",
                "fields": [
                    {"name": "name", "type": "text"},
                    {"name": "location", "type": "geoPoint"}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(created.status, 200);
    assert_eq!(
        collection_field(&created.body, "location")["type"],
        "geoPoint"
    );

    let valid = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/places/records",
            json!({
                "id": "place_1",
                "name": "Istanbul",
                "location": {"lon": 28.9784, "lat": 41.0082}
            }),
        )
        .unwrap(),
    );
    assert_eq!(valid.status, 200);

    let filtered = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/places/records?filter=location.lat%20%3E%3D%2040%20%26%26%20location.lon%20%3C%2030",
    ));
    assert_eq!(filtered.status, 200);
    assert_eq!(filtered.body["totalItems"], 1);
    assert_eq!(filtered.body["items"][0]["id"], "place_1");

    let invalid_shape = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/places/records",
            json!({"location": {"lon": 28.9784, "lat": "41.0082"}}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_shape.status, 400);
    assert_eq!(
        invalid_shape.body["data"]["location"]["code"],
        "validation_invalid_geo_point"
    );

    let invalid_range = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/places/records",
            json!({"location": {"lon": 28.9784, "lat": 91}}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_range.status, 400);
    assert_eq!(
        invalid_range.body["data"]["location"]["code"],
        "validation_invalid_geo_point"
    );
}

#[test]
fn supports_relation_min_select_metadata_and_validation() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let tags = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "tags",
                "fields": [{"name": "label", "type": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(tags.status, 200);

    for record in [
        json!({"id": "tag_1", "label": "rust"}),
        json!({"id": "tag_2", "label": "sqlite"}),
        json!({"id": "tag_3", "label": "pocketbase"}),
    ] {
        let response =
            app.handle(HttpRequest::json("POST", "/api/collections/tags/records", record).unwrap());
        assert_eq!(response.status, 200);
    }

    let posts = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "title", "type": "text"},
                    {
                        "name": "tags",
                        "type": "relation",
                        "collection": "tags",
                        "minSelect": 2,
                        "maxSelect": 3
                    }
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(posts.status, 200);
    let tags_field = collection_field(&posts.body, "tags");
    assert_eq!(tags_field["minSelect"], 2);
    assert_eq!(tags_field["maxSelect"], 3);

    let missing_relation = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Too few"}),
        )
        .unwrap(),
    );
    assert_eq!(missing_relation.status, 400);
    assert_eq!(
        missing_relation.body["data"]["tags"]["code"],
        "validation_min_select"
    );

    let too_few_relations = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Still too few", "tags": ["tag_1"]}),
        )
        .unwrap(),
    );
    assert_eq!(too_few_relations.status, 400);
    assert_eq!(
        too_few_relations.body["data"]["tags"]["code"],
        "validation_min_select"
    );

    let valid = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Enough", "tags": ["tag_1", "tag_2"]}),
        )
        .unwrap(),
    );
    assert_eq!(valid.status, 200);

    let invalid_kind = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "bad_min_select_kind",
                "fields": [{"name": "title", "type": "text", "minSelect": 1}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(invalid_kind.status, 400);

    let invalid_range = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "bad_min_select_range",
                "fields": [{
                    "name": "tags",
                    "type": "relation",
                    "collection": "tags",
                    "minSelect": 2,
                    "maxSelect": 1
                }]
            }),
        )
        .unwrap(),
    );
    assert_eq!(invalid_range.status, 400);
}

#[test]
fn cascades_relation_deletes_for_configured_fields() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    for collection in [
        json!({
            "name": "posts",
            "fields": [{"name": "title", "type": "text"}]
        }),
        json!({
            "name": "comments",
            "fields": [
                {"name": "body", "type": "text"},
                {"name": "post", "type": "relation", "collection": "posts", "cascadeDelete": true}
            ]
        }),
        json!({
            "name": "reactions",
            "fields": [
                {"name": "comment", "type": "relation", "collection": "comments", "cascadeDelete": true}
            ]
        }),
        json!({
            "name": "bookmarks",
            "fields": [
                {"name": "post", "type": "relation", "collection": "posts"}
            ]
        }),
    ] {
        let response =
            app.handle(HttpRequest::json("POST", "/api/collections", collection).unwrap());
        assert_eq!(response.status, 200);
        if response.body["name"] == "comments" {
            assert_eq!(
                collection_field(&response.body, "post")["cascadeDelete"],
                true
            );
        }
    }

    for (collection, record) in [
        ("posts", json!({"id": "post_1", "title": "Cascade source"})),
        ("posts", json!({"id": "post_2", "title": "Keep source"})),
        (
            "comments",
            json!({"id": "comment_1", "body": "delete me", "post": "post_1"}),
        ),
        (
            "comments",
            json!({"id": "comment_2", "body": "delete me too", "post": "post_1"}),
        ),
        (
            "comments",
            json!({"id": "comment_3", "body": "keep me", "post": "post_2"}),
        ),
        (
            "reactions",
            json!({"id": "reaction_1", "comment": "comment_1"}),
        ),
        ("bookmarks", json!({"id": "bookmark_1", "post": "post_1"})),
    ] {
        let response = app.handle(
            HttpRequest::json(
                "POST",
                format!("/api/collections/{collection}/records"),
                record,
            )
            .unwrap(),
        );
        assert_eq!(response.status, 200);
    }

    let exported = app.handle(HttpRequest::new("GET", "/api/collections/meta/export"));
    assert_eq!(exported.status, 200);
    let exported_comments = exported.body["collections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|collection| collection["name"] == "comments")
        .unwrap();
    let exported_post_field = exported_comments["schema"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["name"] == "post")
        .unwrap();
    assert_eq!(exported_post_field["cascadeDelete"], true);

    let deleted = app.handle(HttpRequest::new(
        "DELETE",
        "/api/collections/posts/records/post_1",
    ));
    assert_eq!(deleted.status, 204);

    let comments = app.handle(HttpRequest::new("GET", "/api/collections/comments/records"));
    assert_eq!(comments.status, 200);
    assert_eq!(comments.body["totalItems"], 1);
    assert_eq!(comments.body["items"][0]["id"], "comment_3");

    let reactions = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/reactions/records",
    ));
    assert_eq!(reactions.status, 200);
    assert_eq!(reactions.body["totalItems"], 0);

    let bookmarks = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/bookmarks/records",
    ));
    assert_eq!(bookmarks.status, 200);
    assert_eq!(bookmarks.body["totalItems"], 1);
    assert_eq!(bookmarks.body["items"][0]["id"], "bookmark_1");

    let invalid_kind = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "bad_cascade_kind",
                "fields": [{"name": "title", "type": "text", "cascadeDelete": true}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(invalid_kind.status, 400);
}

#[test]
fn cascade_delete_rolls_back_when_nested_delete_fails() {
    let path = temp_db_path("cascade-rollback");
    let store = Store::open(&path).unwrap();
    store
        .create_collection(CollectionConfig::new(
            "posts",
            [CollectionField::new("title", CollectionFieldKind::Text)],
        ))
        .unwrap();

    let mut post_relation = CollectionField::relation("post", "posts");
    post_relation.cascade_delete = true;
    store
        .create_collection(CollectionConfig::new(
            "comments",
            [
                CollectionField::new("body", CollectionFieldKind::Text),
                post_relation,
            ],
        ))
        .unwrap();

    store
        .create_record("posts", json!({"id": "post_1", "title": "Keep me"}))
        .unwrap();
    store
        .create_record(
            "comments",
            json!({"id": "comment_1", "body": "Keep me too", "post": "post_1"}),
        )
        .unwrap();

    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            CREATE TRIGGER fail_comment_delete
            BEFORE DELETE ON "_rb_records_comments"
            WHEN OLD.id = 'comment_1'
            BEGIN
                SELECT RAISE(ABORT, 'cascade child delete failed');
            END;
            "#,
        )
        .unwrap();
    }

    let err = store.delete_record("posts", "post_1").unwrap_err();
    assert!(err.to_string().contains("cascade child delete failed"));

    let posts = store.list_records("posts", ListOptions::default()).unwrap();
    assert_eq!(posts.total_items, 1);
    assert_eq!(posts.items[0]["id"], "post_1");

    let comments = store
        .list_records("comments", ListOptions::default())
        .unwrap();
    assert_eq!(comments.total_items, 1);
    assert_eq!(comments.items[0]["id"], "comment_1");
}

#[test]
fn relation_cascade_delete_handles_cycles() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    for collection in [
        json!({
            "name": "nodes_a",
            "fields": [{
                "name": "b",
                "type": "relation",
                "collection": "nodes_b",
                "cascadeDelete": true
            }]
        }),
        json!({
            "name": "nodes_b",
            "fields": [{
                "name": "a",
                "type": "relation",
                "collection": "nodes_a",
                "cascadeDelete": true
            }]
        }),
    ] {
        let response =
            app.handle(HttpRequest::json("POST", "/api/collections", collection).unwrap());
        assert_eq!(response.status, 200);
    }

    let node_a = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/nodes_a/records",
            json!({"id": "node_a_1"}),
        )
        .unwrap(),
    );
    assert_eq!(node_a.status, 200);

    let node_b = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/nodes_b/records",
            json!({"id": "node_b_1", "a": "node_a_1"}),
        )
        .unwrap(),
    );
    assert_eq!(node_b.status, 200);

    let linked_a = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/nodes_a/records/node_a_1",
            json!({"b": "node_b_1"}),
        )
        .unwrap(),
    );
    assert_eq!(linked_a.status, 200);

    let deleted = app.handle(HttpRequest::new(
        "DELETE",
        "/api/collections/nodes_a/records/node_a_1",
    ));
    assert_eq!(deleted.status, 204);

    let remaining_a = app.handle(HttpRequest::new("GET", "/api/collections/nodes_a/records"));
    assert_eq!(remaining_a.status, 200);
    assert_eq!(remaining_a.body["totalItems"], 0);

    let remaining_b = app.handle(HttpRequest::new("GET", "/api/collections/nodes_b/records"));
    assert_eq!(remaining_b.status, 200);
    assert_eq!(remaining_b.body["totalItems"], 0);
}

#[test]
fn enforces_required_and_text_field_options_on_records() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let collection = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {
                        "name": "title",
                        "type": "text",
                        "required": true,
                        "min": 3,
                        "max": 8,
                        "pattern": "^[A-Z].+"
                    },
                    {"name": "body", "type": "text"}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(collection.status, 200);

    let missing = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"body": "missing title"}),
        )
        .unwrap(),
    );
    assert_eq!(missing.status, 400);
    assert_eq!(missing.body["data"]["title"]["code"], "validation_required");

    let too_short = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Hi"}),
        )
        .unwrap(),
    );
    assert_eq!(too_short.status, 400);
    assert_eq!(
        too_short.body["data"]["title"]["code"],
        "validation_min_text_constraint"
    );

    let too_long = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "LongTitle"}),
        )
        .unwrap(),
    );
    assert_eq!(too_long.status, 400);
    assert_eq!(
        too_long.body["data"]["title"]["code"],
        "validation_max_text_constraint"
    );

    let pattern = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "rusty"}),
        )
        .unwrap(),
    );
    assert_eq!(pattern.status, 400);
    assert_eq!(
        pattern.body["data"]["title"]["code"],
        "validation_pattern_constraint"
    );

    let created = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"id": "post_1", "title": "Rusty", "body": "first"}),
        )
        .unwrap(),
    );
    assert_eq!(created.status, 200);

    let body_only = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_1",
            json!({"body": "keeps existing required title"}),
        )
        .unwrap(),
    );
    assert_eq!(body_only.status, 200);
    assert_eq!(body_only.body["title"], "Rusty");

    let cleared_required = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_1",
            json!({"title": ""}),
        )
        .unwrap(),
    );
    assert_eq!(cleared_required.status, 400);
    assert_eq!(
        cleared_required.body["data"]["title"]["code"],
        "validation_required"
    );
}

#[test]
fn enforces_non_text_field_option_shapes_on_records() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let tags = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "tags",
                "fields": [{"name": "label", "type": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(tags.status, 200);

    for record in [
        json!({"id": "tag_1", "label": "rust"}),
        json!({"id": "tag_2", "label": "sqlite"}),
    ] {
        let response =
            app.handle(HttpRequest::json("POST", "/api/collections/tags/records", record).unwrap());
        assert_eq!(response.status, 200);
    }

    let posts = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "published", "type": "bool", "required": true},
                    {"name": "score", "type": "number", "min": 1, "max": 20},
                    {"name": "contact", "type": "email"},
                    {"name": "publishedAt", "type": "datetime"},
                    {"name": "status", "type": "select", "values": ["draft", "published"]},
                    {"name": "roles", "type": "select", "values": ["reader", "writer", "admin"], "maxSelect": 2},
                    {"name": "tags", "type": "relation", "collection": "tags", "maxSelect": 1},
                    {"name": "scopes", "type": "array"},
                    {"name": "payload", "type": "json"}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(posts.status, 200);

    let valid = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({
                "id": "post_1",
                "published": true,
                "score": 10,
                "contact": "burak@example.com",
                "publishedAt": "2024-11-10 18:45:27.123Z",
                "status": "draft",
                "roles": ["reader"],
                "tags": "tag_1",
                "scopes": ["read"],
                "payload": {"ok": true}
            }),
        )
        .unwrap(),
    );
    assert_eq!(valid.status, 200);

    let select_filter = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts/records?filter=status%20%3D%20%27draft%27%20%26%26%20roles%20%3F%3D%20%27reader%27",
    ));
    assert_eq!(select_filter.status, 200);
    assert_eq!(select_filter.body["totalItems"], 1);
    assert_eq!(select_filter.body["items"][0]["id"], "post_1");

    let invalid_bool = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"published": "true"}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_bool.status, 400);
    assert_eq!(
        invalid_bool.body["data"]["published"]["code"],
        "validation_invalid_bool"
    );

    let invalid_number = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"published": true, "score": "10"}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_number.status, 400);
    assert_eq!(
        invalid_number.body["data"]["score"]["code"],
        "validation_invalid_number"
    );

    let too_small_number = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"published": true, "score": 0}),
        )
        .unwrap(),
    );
    assert_eq!(too_small_number.status, 400);
    assert_eq!(
        too_small_number.body["data"]["score"]["code"],
        "validation_min_number_constraint"
    );

    let too_large_number = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"published": true, "score": 21}),
        )
        .unwrap(),
    );
    assert_eq!(too_large_number.status, 400);
    assert_eq!(
        too_large_number.body["data"]["score"]["code"],
        "validation_max_number_constraint"
    );

    let invalid_datetime_shape = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"published": true, "publishedAt": 123}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_datetime_shape.status, 400);
    assert_eq!(
        invalid_datetime_shape.body["data"]["publishedAt"]["code"],
        "validation_invalid_datetime"
    );

    let invalid_datetime_format = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"published": true, "publishedAt": "2024-11-10T18:45:27Z"}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_datetime_format.status, 400);
    assert_eq!(
        invalid_datetime_format.body["data"]["publishedAt"]["code"],
        "validation_invalid_datetime"
    );

    let invalid_datetime_calendar = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"published": true, "publishedAt": "2024-02-30 18:45:27.123Z"}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_datetime_calendar.status, 400);
    assert_eq!(
        invalid_datetime_calendar.body["data"]["publishedAt"]["code"],
        "validation_invalid_datetime"
    );

    let invalid_array = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"published": true, "scopes": "read"}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_array.status, 400);
    assert_eq!(
        invalid_array.body["data"]["scopes"]["code"],
        "validation_invalid_array"
    );

    let invalid_select_shape = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"published": true, "status": ["draft"]}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_select_shape.status, 400);
    assert_eq!(
        invalid_select_shape.body["data"]["status"]["code"],
        "validation_invalid_select"
    );

    let invalid_select_value = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"published": true, "status": "archived"}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_select_value.status, 400);
    assert_eq!(
        invalid_select_value.body["data"]["status"]["code"],
        "validation_invalid_select"
    );

    let invalid_multi_select_shape = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"published": true, "roles": "reader"}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_multi_select_shape.status, 400);
    assert_eq!(
        invalid_multi_select_shape.body["data"]["roles"]["code"],
        "validation_invalid_select"
    );

    let invalid_multi_select_value = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"published": true, "roles": ["reader", "ghost"]}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_multi_select_value.status, 400);
    assert_eq!(
        invalid_multi_select_value.body["data"]["roles"]["code"],
        "validation_invalid_select"
    );

    let too_many_select_values = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"published": true, "roles": ["reader", "writer", "admin"]}),
        )
        .unwrap(),
    );
    assert_eq!(too_many_select_values.status, 400);
    assert_eq!(
        too_many_select_values.body["data"]["roles"]["code"],
        "validation_max_select"
    );

    let invalid_relation_shape = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"published": true, "tags": 123}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_relation_shape.status, 400);
    assert_eq!(
        invalid_relation_shape.body["data"]["tags"]["code"],
        "validation_invalid_relation"
    );

    let missing_relation_target = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"published": true, "tags": "tag_missing"}),
        )
        .unwrap(),
    );
    assert_eq!(missing_relation_target.status, 400);
    assert_eq!(
        missing_relation_target.body["data"]["tags"]["code"],
        "validation_invalid_relation"
    );

    let too_many_relations = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"published": true, "tags": ["tag_1", "tag_2"]}),
        )
        .unwrap(),
    );
    assert_eq!(too_many_relations.status, 400);
    assert_eq!(
        too_many_relations.body["data"]["tags"]["code"],
        "validation_max_select"
    );

    let invalid_email = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"published": true, "contact": "not-email"}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_email.status, 400);
    assert_eq!(
        invalid_email.body["data"]["contact"]["code"],
        "validation_is_email"
    );

    let invalid_patch = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_1",
            json!({"published": "yes"}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_patch.status, 400);
    assert_eq!(
        invalid_patch.body["data"]["published"]["code"],
        "validation_invalid_bool"
    );

    let invalid_relation_patch = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_1",
            json!({"tags": "tag_missing"}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_relation_patch.status, 400);
    assert_eq!(
        invalid_relation_patch.body["data"]["tags"]["code"],
        "validation_invalid_relation"
    );

    let invalid_number_patch = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_1",
            json!({"score": 30}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_number_patch.status, 400);
    assert_eq!(
        invalid_number_patch.body["data"]["score"]["code"],
        "validation_max_number_constraint"
    );

    let invalid_select_patch = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_1",
            json!({"status": "archived"}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_select_patch.status, 400);
    assert_eq!(
        invalid_select_patch.body["data"]["status"]["code"],
        "validation_invalid_select"
    );

    let invalid_datetime_patch = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_1",
            json!({"publishedAt": "2023-02-29 00:00:00.000Z"}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_datetime_patch.status, 400);
    assert_eq!(
        invalid_datetime_patch.body["data"]["publishedAt"]["code"],
        "validation_invalid_datetime"
    );

    let valid_patch = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_1",
            json!({
                "score": 11,
                "publishedAt": "2024-12-01 09:00:00.000Z",
                "status": "published",
                "roles": ["reader", "writer"]
            }),
        )
        .unwrap(),
    );
    assert_eq!(valid_patch.status, 200);
    assert_eq!(valid_patch.body["published"], true);
    assert_eq!(valid_patch.body["score"], 11);
    assert_eq!(valid_patch.body["publishedAt"], "2024-12-01 09:00:00.000Z");
    assert_eq!(valid_patch.body["status"], "published");
    assert_eq!(valid_patch.body["roles"], json!(["reader", "writer"]));
}

#[test]
fn enforces_json_field_options_on_records() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let collection = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "events",
                "fields": [
                    {"name": "title", "type": "text"},
                    {"name": "payload", "type": "json", "required": true, "maxSize": 20},
                    {"name": "notes", "type": "json", "maxSize": 8}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(collection.status, 200);

    let valid_object = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/events/records",
            json!({"id": "event_1", "title": "Object", "payload": {"ok": true}}),
        )
        .unwrap(),
    );
    assert_eq!(valid_object.status, 200);

    let valid_scalar = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/events/records/event_1",
            json!({"payload": false, "notes": null}),
        )
        .unwrap(),
    );
    assert_eq!(valid_scalar.status, 200);
    assert_eq!(valid_scalar.body["payload"], false);
    assert_eq!(valid_scalar.body["notes"], JsonValue::Null);

    for empty in [JsonValue::Null, json!(""), json!([]), json!({})] {
        let response = app.handle(
            HttpRequest::json(
                "POST",
                "/api/collections/events/records",
                json!({"title": "Empty JSON", "payload": empty}),
            )
            .unwrap(),
        );
        assert_eq!(response.status, 400);
        assert_eq!(
            response.body["data"]["payload"]["code"],
            "validation_required"
        );
    }

    let too_large = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/events/records",
            json!({"title": "Too large", "payload": {"message": "this is too large"}}),
        )
        .unwrap(),
    );
    assert_eq!(too_large.status, 400);
    assert_eq!(
        too_large.body["data"]["payload"]["code"],
        "validation_max_size"
    );

    let too_large_patch = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/events/records/event_1",
            json!({"notes": {"long": "value"}}),
        )
        .unwrap(),
    );
    assert_eq!(too_large_patch.status, 400);
    assert_eq!(
        too_large_patch.body["data"]["notes"]["code"],
        "validation_max_size"
    );
}

#[test]
fn applies_number_select_and_relation_record_modifiers() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let tags = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "tags",
                "fields": [{"name": "label", "type": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(tags.status, 200);
    for record in [
        json!({"id": "tag_1", "label": "rust"}),
        json!({"id": "tag_2", "label": "sqlite"}),
    ] {
        let response =
            app.handle(HttpRequest::json("POST", "/api/collections/tags/records", record).unwrap());
        assert_eq!(response.status, 200);
    }

    let posts = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "score", "type": "number"},
                    {"name": "roles", "type": "select", "values": ["reader", "writer", "admin", "owner"], "maxSelect": 3},
                    {"name": "tags", "type": "relation", "collection": "tags", "maxSelect": 3}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(posts.status, 200);

    let created = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({
                "id": "post_1",
                "score+": 2,
                "+roles": ["writer"],
                "roles+": "reader",
                "tags+": "tag_1"
            }),
        )
        .unwrap(),
    );
    assert_eq!(created.status, 200);
    assert_eq!(created.body["score"], 2.0);
    assert_eq!(created.body["roles"], json!(["writer", "reader"]));
    assert_eq!(created.body["tags"], json!(["tag_1"]));

    let updated = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_1",
            json!({
                "score+": 3,
                "score-": 1,
                "roles-": "reader",
                "roles+": "admin",
                "+tags": "tag_2",
                "tags-": "tag_1"
            }),
        )
        .unwrap(),
    );
    assert_eq!(updated.status, 200);
    assert_eq!(updated.body["score"], 4.0);
    assert_eq!(updated.body["roles"], json!(["writer", "admin"]));
    assert_eq!(updated.body["tags"], json!(["tag_2"]));

    let invalid_number = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_1",
            json!({"score+": "bad"}),
        )
        .unwrap(),
    );
    assert_eq!(invalid_number.status, 400);
    assert_eq!(
        invalid_number.body["data"]["score+"]["code"],
        "validation_invalid_modifier"
    );

    let too_many_roles = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_1",
            json!({"roles+": ["reader", "owner"]}),
        )
        .unwrap(),
    );
    assert_eq!(too_many_roles.status, 400);
    assert_eq!(
        too_many_roles.body["data"]["roles"]["code"],
        "validation_max_select"
    );

    let missing_relation = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_1",
            json!({"tags+": "tag_missing"}),
        )
        .unwrap(),
    );
    assert_eq!(missing_relation.status, 400);
    assert_eq!(
        missing_relation.body["data"]["tags"]["code"],
        "validation_invalid_relation"
    );
}

#[test]
fn truncates_and_deletes_collections() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let collection_response = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [{"name": "title", "kind": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(collection_response.status, 200);

    let created = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Rusty Base"}),
        )
        .unwrap(),
    );
    assert_eq!(created.status, 200);

    let truncate = app.handle(HttpRequest::new(
        "DELETE",
        "/api/collections/posts/truncate",
    ));
    assert_eq!(truncate.status, 204);

    let empty = app.handle(HttpRequest::new("GET", "/api/collections/posts/records"));
    assert_eq!(empty.status, 200);
    assert_eq!(empty.body["totalItems"], 0);

    let delete = app.handle(HttpRequest::new("DELETE", "/api/collections/posts"));
    assert_eq!(delete.status, 204);

    let collection = app.handle(HttpRequest::new("GET", "/api/collections/posts"));
    assert_eq!(collection.status, 404);

    let records = app.handle(HttpRequest::new("GET", "/api/collections/posts/records"));
    assert_eq!(records.status, 404);
}

#[test]
fn imports_collections_and_optionally_deletes_missing_metadata() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let posts = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "title", "kind": "text"},
                    {"name": "legacy", "kind": "text"}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(posts.status, 200);

    let comments = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "comments",
                "fields": [{"name": "body", "kind": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(comments.status, 200);

    let created = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Rusty Base", "legacy": "keep for now"}),
        )
        .unwrap(),
    );
    assert_eq!(created.status, 200);

    let merge_import = app.handle(
        HttpRequest::json(
            "PUT",
            "/api/collections/import",
            json!({
                "collections": [{
                    "name": "posts",
                    "schema": [
                        {"name": "title", "type": "text"},
                        {"name": "tags", "type": "array"}
                    ],
                    "listRule": "title ~ 'Rusty'"
                }]
            }),
        )
        .unwrap(),
    );
    assert_eq!(merge_import.status, 204);

    let comments_after_merge = app.handle(HttpRequest::new("GET", "/api/collections/comments"));
    assert_eq!(comments_after_merge.status, 200);

    let posts_after_merge = app.handle(HttpRequest::new("GET", "/api/collections/posts"));
    assert_eq!(posts_after_merge.status, 200);
    assert_eq!(user_collection_fields(&posts_after_merge.body).len(), 3);
    assert_eq!(posts_after_merge.body["listRule"], "title ~ 'Rusty'");

    let list_after_merge = app.handle(HttpRequest::new("GET", "/api/collections/posts/records"));
    assert_eq!(list_after_merge.status, 200);
    assert_eq!(list_after_merge.body["items"][0]["legacy"], "keep for now");

    let replace_import = app.handle(
        HttpRequest::json(
            "PUT",
            "/api/collections/import",
            json!({
                "deleteMissing": true,
                "collections": [
                    {
                        "name": "posts",
                        "schema": [
                            {"name": "title", "type": "text"},
                            {"name": "tags", "type": "array"}
                        ],
                        "listRule": "title ~ 'Rusty'"
                    },
                    {
                        "name": "authors",
                        "schema": [{"name": "name", "type": "text"}]
                    }
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(replace_import.status, 204);

    let comments_after_replace = app.handle(HttpRequest::new("GET", "/api/collections/comments"));
    assert_eq!(comments_after_replace.status, 404);

    let posts_after_replace = app.handle(HttpRequest::new("GET", "/api/collections/posts"));
    assert_eq!(posts_after_replace.status, 200);
    assert_eq!(user_collection_fields(&posts_after_replace.body).len(), 2);

    let list_after_replace = app.handle(HttpRequest::new("GET", "/api/collections/posts/records"));
    assert_eq!(list_after_replace.status, 200);
    assert_eq!(list_after_replace.body["totalItems"], 1);
    assert_eq!(list_after_replace.body["items"][0]["title"], "Rusty Base");
    assert!(list_after_replace.body["items"][0].get("legacy").is_none());

    let new_author = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/authors/records",
            json!({"name": "Ada"}),
        )
        .unwrap(),
    );
    assert_eq!(new_author.status, 200);
    assert_eq!(new_author.body["name"], "Ada");
}

#[test]
fn returns_collection_scaffolds_and_import_ready_export_payload() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let scaffolds = app.handle(HttpRequest::new("GET", "/api/collections/meta/scaffolds"));
    assert_eq!(scaffolds.status, 200);
    assert_eq!(scaffolds.body["base"]["type"], "base");
    assert_eq!(scaffolds.body["auth"]["type"], "auth");
    assert_eq!(scaffolds.body["view"]["type"], "view");
    assert_eq!(scaffolds.body["base"]["fields"][0]["name"], "id");
    assert_eq!(scaffolds.body["base"]["fields"][0]["type"], "text");
    assert_eq!(
        collection_field(&scaffolds.body["base"], "created")["type"],
        "autodate"
    );
    assert_eq!(
        collection_field(&scaffolds.body["base"], "updated")["onUpdate"],
        true
    );
    assert_eq!(
        scaffolds.body["auth"]["passwordAuth"]["identityFields"][0],
        "email"
    );
    assert_eq!(scaffolds.body["view"]["viewQuery"], "");

    let created = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "title", "kind": "text"},
                    {"name": "published", "kind": "bool"}
                ],
                "indexes": ["CREATE INDEX idx_posts_title ON posts (title)"],
                "listRule": "published = true"
            }),
        )
        .unwrap(),
    );
    assert_eq!(created.status, 200);
    assert_eq!(
        created.body["indexes"],
        json!(["CREATE INDEX idx_posts_title ON posts (title)"])
    );

    let exported = app.handle(HttpRequest::new("GET", "/api/collections/meta/export"));
    assert_eq!(exported.status, 200);
    assert_eq!(exported.body["collections"][0]["name"], "posts");
    assert_eq!(
        exported.body["collections"][0]["indexes"],
        json!(["CREATE INDEX idx_posts_title ON posts (title)"])
    );
    assert_eq!(
        exported.body["collections"][0]["schema"][0]["name"],
        "title"
    );
    assert_eq!(exported.body["collections"][0]["schema"][0]["type"], "text");
    let exported_title_field_id = exported.body["collections"][0]["schema"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(exported_title_field_id.starts_with("text"));
    assert!(exported.body["collections"][0]["schema"][0]
        .get("kind")
        .is_none());
    assert_eq!(
        exported.body["collections"][0]["listRule"],
        "published = true"
    );

    let fresh = RustyBaseApp::new(Store::open_in_memory().unwrap());
    let imported = fresh.handle(
        HttpRequest::json("PUT", "/api/collections/import", exported.body.clone()).unwrap(),
    );
    assert_eq!(imported.status, 204);

    let imported_posts = fresh.handle(HttpRequest::new("GET", "/api/collections/posts"));
    assert_eq!(imported_posts.status, 200);
    assert_eq!(user_collection_fields(&imported_posts.body).len(), 2);
    assert_eq!(
        collection_field(&imported_posts.body, "title")["id"],
        exported_title_field_id
    );
    assert_eq!(
        imported_posts.body["indexes"],
        json!(["CREATE INDEX idx_posts_title ON posts (title)"])
    );
    assert!(imported_posts.body.get("indexWarnings").is_none());
    assert_eq!(imported_posts.body["listRule"], "published = true");

    let invalid_index = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "bad_indexes",
                "indexes": ["CREATE INDEX bad\u{0000}idx ON bad_indexes (title)"],
                "fields": [{"name": "title", "type": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(invalid_index.status, 400);
}

#[test]
fn collection_indexes_execute_only_safe_scalar_plans() {
    let path = temp_db_path("safe-index-plan");
    let app = RustyBaseApp::new(Store::open(&path).unwrap());

    let created = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "title", "type": "text"},
                    {"name": "meta", "type": "json"}
                ],
                "indexes": [
                    "CREATE INDEX idx_posts_title ON posts (title)",
                    "CREATE UNIQUE INDEX idx_posts_unique_title ON posts (title)",
                    "CREATE INDEX idx_posts_title_meta ON posts (title, meta)",
                    "CREATE INDEX idx_posts_meta ON posts (meta)"
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(created.status, 200);
    assert_eq!(
        created.body["indexes"],
        json!([
            "CREATE INDEX idx_posts_title ON posts (title)",
            "CREATE UNIQUE INDEX idx_posts_unique_title ON posts (title)",
            "CREATE INDEX idx_posts_title_meta ON posts (title, meta)",
            "CREATE INDEX idx_posts_meta ON posts (meta)"
        ])
    );
    let index_warnings = created.body["indexWarnings"].as_array().unwrap();
    assert_eq!(index_warnings.len(), 3);
    assert_eq!(index_warnings[0]["code"], "metadata_only_index");
    assert_eq!(
        index_warnings
            .iter()
            .map(|warning| warning["index"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "CREATE UNIQUE INDEX idx_posts_unique_title ON posts (title)",
            "CREATE INDEX idx_posts_title_meta ON posts (title, meta)",
            "CREATE INDEX idx_posts_meta ON posts (meta)"
        ]
    );

    {
        let conn = Connection::open(&path).unwrap();
        let raw_index_count: i64 = conn
            .query_row(
                r#"
                SELECT COUNT(*)
                FROM sqlite_master
                WHERE type = 'index'
                    AND name IN (
                        'idx_posts_title',
                        'idx_posts_unique_title',
                        'idx_posts_title_meta',
                        'idx_posts_meta'
                    )
                "#,
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(raw_index_count, 0);

        let safe_index_count: i64 = conn
            .query_row(
                r#"
                SELECT COUNT(*)
                FROM sqlite_master
                WHERE type = 'index'
                    AND tbl_name = '_rb_records_posts'
                    AND name LIKE '_rb_idx_posts_%'
                "#,
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(safe_index_count, 1);

        let (safe_index_name, safe_index_sql): (String, String) = conn
            .query_row(
                r#"
                SELECT name, sql
                FROM sqlite_master
                WHERE type = 'index'
                    AND tbl_name = '_rb_records_posts'
                    AND name LIKE '_rb_idx_posts_%'
                "#,
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(safe_index_name.starts_with("_rb_idx_posts_"));
        assert!(safe_index_sql.contains(r#"json_extract("data""#));
        assert!(safe_index_sql.contains("$.title"));
    }

    let patched = app.handle(
        HttpRequest::json("PATCH", "/api/collections/posts", json!({"indexes": []})).unwrap(),
    );
    assert_eq!(patched.status, 200);
    assert!(patched.body.get("indexWarnings").is_none());

    let conn = Connection::open(&path).unwrap();
    let remaining_safe_indexes: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name LIKE '_rb_idx_posts_%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(remaining_safe_indexes, 0);

    drop(conn);
    drop(app);
    fs::remove_file(path).ok();
}

#[test]
fn supports_read_only_view_collection_queries() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let posts = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "title", "type": "text"},
                    {"name": "published", "type": "bool"}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(posts.status, 200);

    for record in [
        json!({"id": "post_1", "title": "Rusty Base", "published": true}),
        json!({"id": "post_2", "title": "Draft Note", "published": false}),
    ] {
        let response = app
            .handle(HttpRequest::json("POST", "/api/collections/posts/records", record).unwrap());
        assert_eq!(response.status, 200);
    }

    let view_query = r#"SELECT id, json_extract(data, '$.title') AS title, created, updated FROM "_rb_records_posts" WHERE json_extract(data, '$.published') = 1"#;
    let created_view = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "published_posts",
                "type": "view",
                "viewQuery": view_query,
                "fields": [{"name": "title", "type": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(created_view.status, 200);
    assert_eq!(created_view.body["type"], "view");
    assert_eq!(created_view.body["viewQuery"], view_query);
    assert_eq!(
        collection_field(&created_view.body, "title")["type"],
        "text"
    );

    let list = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/published_posts/records?filter=title%20~%20%27Rusty%27",
    ));
    assert_eq!(list.status, 200);
    assert_eq!(list.body["totalItems"], 1);
    assert_eq!(list.body["items"][0]["id"], "post_1");
    assert_eq!(list.body["items"][0]["title"], "Rusty Base");
    assert_eq!(list.body["items"][0]["collectionName"], "published_posts");

    let record = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/published_posts/records/post_1",
    ));
    assert_eq!(record.status, 200);
    assert_eq!(record.body["title"], "Rusty Base");

    let hidden = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/published_posts/records/post_2",
    ));
    assert_eq!(hidden.status, 404);

    let create_denied = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/published_posts/records",
            json!({"id": "post_3", "title": "Nope"}),
        )
        .unwrap(),
    );
    assert_eq!(create_denied.status, 400);

    let patch_denied = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/published_posts/records/post_1",
            json!({"title": "Nope"}),
        )
        .unwrap(),
    );
    assert_eq!(patch_denied.status, 400);

    let delete_denied = app.handle(HttpRequest::new(
        "DELETE",
        "/api/collections/published_posts/records/post_1",
    ));
    assert_eq!(delete_denied.status, 400);

    let exported = app.handle(HttpRequest::new("GET", "/api/collections/meta/export"));
    assert_eq!(exported.status, 200);
    let exported_view = exported.body["collections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|collection| collection["name"] == "published_posts")
        .unwrap();
    assert_eq!(exported_view["type"], "view");
    assert_eq!(exported_view["viewQuery"], view_query);

    let invalid_view = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "bad_view",
                "type": "view",
                "viewQuery": "DELETE FROM _rb_records_posts",
                "fields": []
            }),
        )
        .unwrap(),
    );
    assert_eq!(invalid_view.status, 400);

    for (name, table, query) in [
        (
            "bad_auth_tokens_view",
            "_rb_auth_tokens",
            r#"SELECT token AS id FROM "_rb_auth_tokens""#,
        ),
        (
            "bad_settings_view",
            "_rb_settings",
            r#"SELECT key AS id FROM _rb_settings"#,
        ),
        (
            "bad_files_view",
            "_rb_files",
            r#"SELECT filename AS id FROM [_rb_files]"#,
        ),
        (
            "bad_auth_action_tokens_view",
            "_rb_auth_action_tokens",
            r#"SELECT token AS id FROM `_rb_auth_action_tokens`"#,
        ),
        (
            "bad_external_accounts_view",
            "_rb_auth_external_accounts",
            r#"SELECT provider_id AS id FROM "_rb_auth_external_accounts""#,
        ),
        (
            "bad_file_tokens_view",
            "_rb_file_tokens",
            r#"SELECT token AS id FROM "_rb_file_tokens""#,
        ),
        (
            "bad_collections_view",
            "_rb_collections",
            r#"SELECT name AS id FROM "_rb_collections""#,
        ),
        (
            "bad_sqlite_schema_view",
            "sqlite_master",
            r#"SELECT name AS id FROM sqlite_master"#,
        ),
        (
            "bad_pragma_table_info_view",
            "pragma_table_info",
            r#"SELECT name AS id FROM pragma_table_info('_rb_auth_tokens')"#,
        ),
    ] {
        let denied = app.handle(
            HttpRequest::json(
                "POST",
                "/api/collections",
                json!({
                    "name": name,
                    "type": "view",
                    "viewQuery": query,
                    "fields": []
                }),
            )
            .unwrap(),
        );
        assert_eq!(denied.status, 400, "{table} should be denied");
        assert!(denied.body["message"].as_str().unwrap().contains(table));
    }

    let unsafe_function_view = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "unsafe_function_view",
                "type": "view",
                "viewQuery": "SELECT load_extension('missing') AS id",
                "fields": []
            }),
        )
        .unwrap(),
    );
    assert_eq!(unsafe_function_view.status, 200);
    let unsafe_function_list = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/unsafe_function_view/records",
    ));
    assert_eq!(unsafe_function_list.status, 400);
    assert!(unsafe_function_list.body["message"]
        .as_str()
        .unwrap()
        .contains("viewQuery"));

    for (name, query, expected_message) in [
        (
            "duplicate_view_columns",
            r#"SELECT id, id AS id FROM "_rb_records_posts""#,
            "invalid column name",
        ),
        (
            "reserved_view_collection_name",
            r#"SELECT id, 'spoof' AS collectionName FROM "_rb_records_posts""#,
            "reserved column",
        ),
        (
            "reserved_view_expand",
            r#"SELECT id, '{}' AS expand FROM "_rb_records_posts""#,
            "reserved column",
        ),
    ] {
        let created = app.handle(
            HttpRequest::json(
                "POST",
                "/api/collections",
                json!({
                    "name": name,
                    "type": "view",
                    "viewQuery": query,
                    "fields": []
                }),
            )
            .unwrap(),
        );
        assert_eq!(created.status, 200);

        let listed = app.handle(HttpRequest::new(
            "GET",
            format!("/api/collections/{name}/records"),
        ));
        assert_eq!(listed.status, 400);
        assert!(listed.body["message"]
            .as_str()
            .unwrap()
            .contains(expected_message));
    }

    let delete_view = app.handle(HttpRequest::new(
        "DELETE",
        "/api/collections/published_posts",
    ));
    assert_eq!(delete_view.status, 204);
}

#[test]
fn expands_single_multi_and_nested_relation_records() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    for collection in [
        json!({
            "name": "profiles",
            "fields": [{"name": "bio", "kind": "text"}]
        }),
        json!({
            "name": "authors",
            "fields": [
                {"name": "name", "kind": "text"},
                {
                    "name": "profile",
                    "kind": "relation",
                    "collectionId": "profiles",
                    "maxSelect": 1
                }
            ]
        }),
        json!({
            "name": "tags",
            "fields": [{"name": "label", "kind": "text"}]
        }),
        json!({
            "name": "posts",
            "fields": [
                {"name": "title", "kind": "text"},
                {
                    "name": "author",
                    "kind": "relation",
                    "collection": "authors",
                    "maxSelect": 1
                },
                {
                    "name": "tags",
                    "kind": "relation",
                    "collection": "tags",
                    "maxSelect": 5
                }
            ]
        }),
    ] {
        let response =
            app.handle(HttpRequest::json("POST", "/api/collections", collection).unwrap());
        assert_eq!(response.status, 200);
    }

    for (collection, record) in [
        ("profiles", json!({"id": "profile_1", "bio": "Rust writer"})),
        (
            "authors",
            json!({"id": "author_1", "name": "Ada", "profile": "profile_1"}),
        ),
        ("tags", json!({"id": "tag_rust", "label": "rust"})),
        ("tags", json!({"id": "tag_sqlite", "label": "sqlite"})),
        (
            "posts",
            json!({
                "id": "post_1",
                "title": "Rusty Base",
                "author": "author_1",
                "tags": ["tag_rust", "tag_sqlite"]
            }),
        ),
    ] {
        let response = app.handle(
            HttpRequest::json(
                "POST",
                format!("/api/collections/{collection}/records"),
                record,
            )
            .unwrap(),
        );
        assert_eq!(response.status, 200);
    }

    let list = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts/records?expand=author.profile,tags",
    ));
    assert_eq!(list.status, 200);
    assert_eq!(list.body["items"][0]["expand"]["author"]["name"], "Ada");
    assert_eq!(
        list.body["items"][0]["expand"]["author"]["expand"]["profile"]["bio"],
        "Rust writer"
    );
    assert_eq!(list.body["items"][0]["expand"]["tags"][0]["label"], "rust");
    assert_eq!(
        list.body["items"][0]["expand"]["tags"][1]["label"],
        "sqlite"
    );

    let record = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts/records/post_1?expand=author,tags",
    ));
    assert_eq!(record.status, 200);
    assert_eq!(record.body["expand"]["author"]["collectionName"], "authors");
    assert_eq!(record.body["expand"]["tags"][0]["collectionName"], "tags");

    let updated = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_1?expand=author",
            json!({"title": "Rusty Base Expanded"}),
        )
        .unwrap(),
    );
    assert_eq!(updated.status, 200);
    assert_eq!(updated.body["title"], "Rusty Base Expanded");
    assert_eq!(updated.body["expand"]["author"]["name"], "Ada");

    let projected_list = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts/records?expand=author.profile,tags&fields=*,expand.author.name,expand.tags.label",
    ));
    assert_eq!(projected_list.status, 200);
    assert_eq!(projected_list.body["items"][0]["id"], "post_1");
    assert_eq!(
        projected_list.body["items"][0]["expand"]["author"]["name"],
        "Ada"
    );
    assert!(projected_list.body["items"][0]["expand"]["author"]
        .get("collectionName")
        .is_none());
    assert!(projected_list.body["items"][0]["expand"]["author"]
        .get("expand")
        .is_none());
    assert_eq!(
        projected_list.body["items"][0]["expand"]["tags"][0]["label"],
        "rust"
    );
    assert!(projected_list.body["items"][0]["expand"]["tags"][0]
        .get("id")
        .is_none());

    let projected_record = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts/records/post_1?expand=author.profile&fields=title,expand.author.name,expand.author.expand.profile.bio",
    ));
    assert_eq!(projected_record.status, 200);
    assert_eq!(projected_record.body["title"], "Rusty Base Expanded");
    assert!(projected_record.body.get("id").is_none());
    assert_eq!(projected_record.body["expand"]["author"]["name"], "Ada");
    assert_eq!(
        projected_record.body["expand"]["author"]["expand"]["profile"]["bio"],
        "Rust writer"
    );

    let created_projected = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records?fields=title",
            json!({
                "id": "post_2",
                "title": "Only Title",
                "author": "author_1",
                "tags": ["tag_rust"]
            }),
        )
        .unwrap(),
    );
    assert_eq!(created_projected.status, 200);
    assert_eq!(created_projected.body["title"], "Only Title");
    assert!(created_projected.body.get("id").is_none());
}

#[test]
fn omits_expanded_relations_blocked_by_view_rule() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    for collection in [
        json!({
            "name": "tags",
            "fields": [
                {"name": "label", "kind": "text"},
                {"name": "public", "kind": "bool"}
            ],
            "viewRule": "public = true"
        }),
        json!({
            "name": "posts",
            "fields": [
                {"name": "title", "kind": "text"},
                {
                    "name": "primaryTag",
                    "kind": "relation",
                    "collection": "tags",
                    "maxSelect": 1
                },
                {
                    "name": "tags",
                    "kind": "relation",
                    "collection": "tags",
                    "maxSelect": 5
                }
            ]
        }),
    ] {
        let response =
            app.handle(HttpRequest::json("POST", "/api/collections", collection).unwrap());
        assert_eq!(response.status, 200);
    }

    for (collection, record) in [
        (
            "tags",
            json!({"id": "tag_public", "label": "rust", "public": true}),
        ),
        (
            "tags",
            json!({"id": "tag_private", "label": "draft", "public": false}),
        ),
        (
            "posts",
            json!({
                "id": "post_1",
                "title": "Rule-aware expand",
                "primaryTag": "tag_private",
                "tags": ["tag_public", "tag_private"]
            }),
        ),
    ] {
        let response = app.handle(
            HttpRequest::json(
                "POST",
                format!("/api/collections/{collection}/records"),
                record,
            )
            .unwrap(),
        );
        assert_eq!(response.status, 200);
    }

    let record = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts/records/post_1?expand=primaryTag,tags",
    ));
    assert_eq!(record.status, 200);
    assert!(record.body["expand"].get("primaryTag").is_none());
    assert_eq!(record.body["expand"]["tags"].as_array().unwrap().len(), 1);
    assert_eq!(record.body["expand"]["tags"][0]["id"], "tag_public");
}

#[test]
fn returns_forbidden_when_http_create_rule_denies_request() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let collection_response = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "title", "kind": "text"},
                    {"name": "published", "kind": "bool"},
                    {"name": "owner", "kind": "text"},
                    {"name": "score", "kind": "number"}
                ],
                "createRule": "@request.body.owner = @request.auth.id"
            }),
        )
        .unwrap(),
    );
    assert_eq!(collection_response.status, 200);

    let denied = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Denied", "published": true, "owner": "user_1", "score": 10}),
        )
        .unwrap(),
    );
    assert_eq!(denied.status, 403);

    let allowed = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Allowed", "published": true, "owner": "user_1", "score": 10}),
        )
        .unwrap()
        .with_header("X-RB-Auth-ID", "user_1"),
    );
    assert_eq!(allowed.status, 200);
    assert_eq!(allowed.body["title"], "Allowed");
}

#[test]
fn applies_request_isset_modifier_in_create_rules() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let collection_response = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "title", "kind": "text"},
                    {"name": "role", "kind": "text"}
                ],
                "createRule": "@request.body.role:isset = false"
            }),
        )
        .unwrap(),
    );
    assert_eq!(collection_response.status, 200);

    let allowed = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Plain"}),
        )
        .unwrap(),
    );
    assert_eq!(allowed.status, 200);

    let denied = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Sneaky", "role": "admin"}),
        )
        .unwrap(),
    );
    assert_eq!(denied.status, 403);
}

#[test]
fn applies_request_lower_and_length_modifiers_in_create_rules() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let collection_response = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "title", "kind": "text"},
                    {"name": "tags", "kind": "array"}
                ],
                "createRule": "@request.body.title:lower = 'rusty base' && @request.body.tags:length = 2"
            }),
        )
        .unwrap(),
    );
    assert_eq!(collection_response.status, 200);

    let allowed = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Rusty Base", "tags": ["rust", "sqlite"]}),
        )
        .unwrap(),
    );
    assert_eq!(allowed.status, 200);

    let denied = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Rusty Base", "tags": ["rust"]}),
        )
        .unwrap(),
    );
    assert_eq!(denied.status, 403);
}

#[test]
fn applies_request_each_modifier_in_create_rules() {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    let collection_response = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "title", "kind": "text"},
                    {"name": "scopes", "kind": "array"}
                ],
                "createRule": "@request.body.scopes:length > 0 && @request.body.scopes:each ~ 'create'"
            }),
        )
        .unwrap(),
    );
    assert_eq!(collection_response.status, 200);

    let allowed = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Allowed", "scopes": ["post:create", "comment:create"]}),
        )
        .unwrap(),
    );
    assert_eq!(allowed.status, 200);

    let denied = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"title": "Denied", "scopes": ["post:create", "post:delete"]}),
        )
        .unwrap(),
    );
    assert_eq!(denied.status, 403);
}

#[test]
fn updates_and_deletes_records() {
    let store = Store::open_in_memory().unwrap();
    store.create_collection(posts_collection()).unwrap();
    let record = store
        .create_record(
            "posts",
            json!({"id": "post_1", "title": "Old", "published": false, "owner": "user_1", "score": 1}),
        )
        .unwrap();
    assert_eq!(record["id"], "post_1");

    let updated = store
        .update_record("posts", "post_1", json!({"title": "New", "score": 2}))
        .unwrap();
    assert_eq!(updated["title"], "New");
    assert_eq!(updated["score"], 2);

    store.delete_record("posts", "post_1").unwrap();
    let list = store.list_records("posts", ListOptions::default()).unwrap();
    assert_eq!(list.total_items, 0);
}

struct MultipartTestPart {
    name: &'static str,
    filename: Option<&'static str>,
    content_type: Option<&'static str>,
    data: Vec<u8>,
}

fn multipart_field(name: &'static str, value: &'static str) -> MultipartTestPart {
    MultipartTestPart {
        name,
        filename: None,
        content_type: None,
        data: value.as_bytes().to_vec(),
    }
}

fn multipart_file(
    name: &'static str,
    filename: &'static str,
    content_type: &'static str,
    data: &'static [u8],
) -> MultipartTestPart {
    MultipartTestPart {
        name,
        filename: Some(filename),
        content_type: Some(content_type),
        data: data.to_vec(),
    }
}

fn multipart_file_bytes(
    name: &'static str,
    filename: &'static str,
    content_type: &'static str,
    data: Vec<u8>,
) -> MultipartTestPart {
    MultipartTestPart {
        name,
        filename: Some(filename),
        content_type: Some(content_type),
        data,
    }
}

fn multipart_request(
    method: &'static str,
    path: &'static str,
    boundary: &'static str,
    parts: Vec<MultipartTestPart>,
) -> HttpRequest {
    let mut body = Vec::new();
    for part in parts {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        if let Some(filename) = part.filename {
            body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n",
                    part.name, filename
                )
                .as_bytes(),
            );
        } else {
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{}\"\r\n", part.name).as_bytes(),
            );
        }
        if let Some(content_type) = part.content_type {
            body.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        }
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(&part.data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let mut request = HttpRequest::new(method, path).with_header(
        "content-type",
        format!("multipart/form-data; boundary={boundary}"),
    );
    request.body = body;
    request
}

fn png_fixture(width: u32, height: u32) -> Vec<u8> {
    let mut image = image::RgbaImage::new(width, height);
    for (x, y, pixel) in image.enumerate_pixels_mut() {
        let red = (x * 40).min(255) as u8;
        let green = (y * 80).min(255) as u8;
        *pixel = image::Rgba([red, green, 180, 255]);
    }

    let mut output = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image)
        .write_to(&mut output, image::ImageFormat::Png)
        .unwrap();
    output.into_inner()
}

fn image_dimensions(data: &[u8]) -> (u32, u32) {
    let image = image::load_from_memory(data).unwrap();
    (image.width(), image.height())
}

fn expect_realtime_event(connection: &RealtimeConnection) -> RealtimeEvent {
    connection.recv_timeout(Duration::from_millis(200)).unwrap()
}

fn posts_collection() -> CollectionConfig {
    CollectionConfig::new(
        "posts",
        [
            CollectionField::new("title", CollectionFieldKind::Text),
            CollectionField::new("published", CollectionFieldKind::Bool),
            CollectionField::new("owner", CollectionFieldKind::Text),
            CollectionField::new("score", CollectionFieldKind::Number),
        ],
    )
}

fn assert_pocketbase_datetime_value(value: &JsonValue) {
    let value = value.as_str().expect("datetime value must be a string");
    let bytes = value.as_bytes();
    assert_eq!(bytes.len(), 24, "unexpected datetime length: {value}");
    assert_eq!(bytes[4], b'-');
    assert_eq!(bytes[7], b'-');
    assert_eq!(bytes[10], b' ');
    assert_eq!(bytes[13], b':');
    assert_eq!(bytes[16], b':');
    assert_eq!(bytes[19], b'.');
    assert_eq!(bytes[23], b'Z');
    for index in [
        0usize, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22,
    ] {
        assert!(
            bytes[index].is_ascii_digit(),
            "unexpected datetime digit at {index}: {value}"
        );
    }
}

fn collection_field<'a>(collection: &'a JsonValue, name: &str) -> &'a JsonValue {
    collection["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["name"] == name)
        .unwrap_or_else(|| panic!("missing collection field {name}"))
}

fn user_collection_fields(collection: &JsonValue) -> Vec<&JsonValue> {
    collection["fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|field| !matches!(field["name"].as_str(), Some("id" | "created" | "updated")))
        .collect()
}
