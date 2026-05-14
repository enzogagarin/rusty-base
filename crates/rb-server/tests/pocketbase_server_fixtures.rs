use rb_server::{
    HttpRequest, HttpResponse, RealtimeConnection, RealtimeEvent, RustyBaseApp, Store,
};
use rusqlite::{params, Connection};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::BTreeMap,
    env, fs,
    path::PathBuf,
    process,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PocketBaseServerFixture {
    name: String,
    area: String,
    pocket_base_note: String,
    cases: Vec<PocketBaseServerCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PocketBaseServerCase {
    name: String,
    route: String,
    expected_status: u16,
    expected_code: Option<String>,
    pocket_base_note: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FixtureOutcome {
    status: u16,
    code: Option<String>,
}

impl FixtureOutcome {
    fn status(status: u16) -> Self {
        Self { status, code: None }
    }

    fn from_response(response: &HttpResponse) -> Self {
        Self::status(response.status)
    }

    fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }
}

#[test]
fn pocketbase_auth_action_fixture_matches_http_behavior() {
    let fixture = load_server_fixture("auth_actions");
    assert_eq!(fixture.area, "auth_actions");

    let outcomes = run_auth_action_fixture();

    assert_fixture_outcomes(&fixture, outcomes);
}

#[test]
fn pocketbase_auth_context_fixture_matches_http_behavior() {
    let fixture = load_server_fixture("auth_context");
    assert_eq!(fixture.area, "auth_context");

    let outcomes = run_auth_context_fixture();

    assert_fixture_outcomes(&fixture, outcomes);
}

#[test]
fn pocketbase_view_collection_fixture_matches_http_behavior() {
    let fixture = load_server_fixture("view_collections");
    assert_eq!(fixture.area, "view_collections");

    let outcomes = run_view_collection_fixture();

    assert_fixture_outcomes(&fixture, outcomes);
}

#[test]
fn pocketbase_relation_expand_fixture_matches_http_behavior() {
    let fixture = load_server_fixture("relation_expand");
    assert_eq!(fixture.area, "relation_expand");

    let outcomes = run_relation_expand_fixture();

    assert_fixture_outcomes(&fixture, outcomes);
}

#[test]
fn pocketbase_protected_file_fixture_matches_http_behavior() {
    let fixture = load_server_fixture("protected_files");
    assert_eq!(fixture.area, "protected_files");

    let outcomes = run_protected_file_fixture();

    assert_fixture_outcomes(&fixture, outcomes);
}

#[test]
fn pocketbase_realtime_fixture_matches_http_behavior() {
    let fixture = load_server_fixture("realtime");
    assert_eq!(fixture.area, "realtime");

    let outcomes = run_realtime_fixture();

    assert_fixture_outcomes(&fixture, outcomes);
}

#[test]
fn pocketbase_batch_fixture_matches_http_behavior() {
    let fixture = load_server_fixture("batch");
    assert_eq!(fixture.area, "batch");

    let outcomes = run_batch_fixture();

    assert_fixture_outcomes(&fixture, outcomes);
}

#[test]
fn pocketbase_import_export_fixture_matches_http_behavior() {
    let fixture = load_server_fixture("import_export");
    assert_eq!(fixture.area, "import_export");

    let outcomes = run_import_export_fixture();

    assert_fixture_outcomes(&fixture, outcomes);
}

#[test]
fn pocketbase_settings_fixture_matches_http_behavior() {
    let fixture = load_server_fixture("settings");
    assert_eq!(fixture.area, "settings");

    let outcomes = run_settings_fixture();

    assert_fixture_outcomes(&fixture, outcomes);
}

fn load_server_fixture(name: &str) -> PocketBaseServerFixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/pocketbase/server")
        .join(format!("{name}.json"));
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read server fixture {path:?}: {err}"));
    serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("failed to parse server fixture {path:?}: {err}"))
}

fn assert_fixture_outcomes(
    fixture: &PocketBaseServerFixture,
    outcomes: BTreeMap<String, FixtureOutcome>,
) {
    assert!(
        !fixture.name.trim().is_empty(),
        "server fixture name must not be empty"
    );
    assert!(
        !fixture.pocket_base_note.trim().is_empty(),
        "{} is missing a PocketBase behavior note",
        fixture.name
    );
    assert_eq!(
        fixture.cases.len(),
        outcomes.len(),
        "{} fixture cases should match executed outcomes",
        fixture.name
    );

    for case in &fixture.cases {
        assert!(
            !case.route.trim().is_empty(),
            "{} / {} is missing a route",
            fixture.name,
            case.name
        );
        assert!(
            !case.pocket_base_note.trim().is_empty(),
            "{} / {} is missing a PocketBase behavior note",
            fixture.name,
            case.name
        );
        let outcome = outcomes
            .get(&case.name)
            .unwrap_or_else(|| panic!("{} / {} has no executed outcome", fixture.name, case.name));
        assert_eq!(
            outcome.status, case.expected_status,
            "{} / {}",
            fixture.name, case.name
        );
        if let Some(expected_code) = &case.expected_code {
            assert_eq!(
                outcome.code.as_deref(),
                Some(expected_code.as_str()),
                "{} / {}",
                fixture.name,
                case.name
            );
        }
    }
}

fn run_auth_action_fixture() -> BTreeMap<String, FixtureOutcome> {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());
    let mut outcomes = BTreeMap::new();

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
    outcomes.insert(
        "missing verification email requires validation data".to_string(),
        FixtureOutcome::from_response(&missing_email)
            .with_code(json_string(&missing_email, &["data", "email", "code"])),
    );

    let unknown_email = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/request-verification",
            json!({"email": "missing@example.com"}),
        )
        .unwrap(),
    );
    outcomes.insert(
        "unknown verification email remains silent".to_string(),
        FixtureOutcome::from_response(&unknown_email),
    );

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
    outcomes.insert(
        "verification token marks record verified".to_string(),
        FixtureOutcome::from_response(&confirm_verification),
    );

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
    outcomes.insert(
        "reused verification token is rejected".to_string(),
        FixtureOutcome::from_response(&reused_verification),
    );

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
    outcomes.insert(
        "password reset mismatch returns field validation".to_string(),
        FixtureOutcome::from_response(&mismatch)
            .with_code(json_string(&mismatch, &["data", "passwordConfirm", "code"])),
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
    outcomes.insert(
        "password reset token updates password".to_string(),
        FixtureOutcome::from_response(&confirm_reset),
    );

    let old_token_refresh = app.handle(
        HttpRequest::new("POST", "/api/collections/users/auth-refresh")
            .with_header("Authorization", format!("Bearer {old_token}")),
    );
    outcomes.insert(
        "password reset invalidates previous auth token".to_string(),
        FixtureOutcome::from_response(&old_token_refresh),
    );

    let old_password = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    outcomes.insert(
        "old password is denied after reset".to_string(),
        FixtureOutcome::from_response(&old_password),
    );

    let new_password = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "burak@example.com", "password": "new correct horse"}),
        )
        .unwrap(),
    );
    outcomes.insert(
        "new password authenticates after reset".to_string(),
        FixtureOutcome::from_response(&new_password),
    );

    outcomes
}

fn run_auth_context_fixture() -> BTreeMap<String, FixtureOutcome> {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());
    let mut outcomes = BTreeMap::new();

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

    let user = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/records",
            json!({
                "id": "user_1",
                "email": "owner@example.com",
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
                    {"name": "title", "type": "text"},
                    {"name": "owner", "type": "text"}
                ],
                "listRule": "owner = @request.auth.id"
            }),
        )
        .unwrap(),
    );
    assert_eq!(posts.status, 200);

    let post = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"id": "post_1", "title": "Owned", "owner": "user_1"}),
        )
        .unwrap(),
    );
    assert_eq!(post.status, 200);

    let anonymous = app.handle(HttpRequest::new("GET", "/api/collections/posts/records"));
    assert_eq!(anonymous.status, 200);
    assert_eq!(anonymous.body["totalItems"], 0);
    outcomes.insert(
        "anonymous request has empty auth context".to_string(),
        FixtureOutcome::from_response(&anonymous),
    );

    let login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "owner@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(login.status, 200);
    let token = login.body["token"].as_str().unwrap().to_string();

    let authorized = app.handle(
        HttpRequest::new("GET", "/api/collections/posts/records")
            .with_header("Authorization", format!("Bearer {token}")),
    );
    assert_eq!(authorized.status, 200);
    assert_eq!(authorized.body["totalItems"], 1);
    outcomes.insert(
        "valid auth token populates request auth context".to_string(),
        FixtureOutcome::from_response(&authorized),
    );

    app.store().expire_token(&token).unwrap();

    let expired_list = app.handle(
        HttpRequest::new("GET", "/api/collections/posts/records")
            .with_header("Authorization", format!("Bearer {token}")),
    );
    assert_eq!(expired_list.status, 200);
    assert_eq!(expired_list.body["totalItems"], 0);
    outcomes.insert(
        "expired auth token becomes empty rule auth context".to_string(),
        FixtureOutcome::from_response(&expired_list),
    );

    let expired_refresh = app.handle(
        HttpRequest::new("POST", "/api/collections/users/auth-refresh")
            .with_header("Authorization", format!("Bearer {token}")),
    );
    outcomes.insert(
        "expired auth token cannot refresh".to_string(),
        FixtureOutcome::from_response(&expired_refresh),
    );

    let second_login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": "owner@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(second_login.status, 200);
    let revoked_token = second_login.body["token"].as_str().unwrap().to_string();
    let logout = app.handle(
        HttpRequest::new("POST", "/api/collections/users/auth-logout")
            .with_header("Authorization", format!("Bearer {revoked_token}")),
    );
    assert_eq!(logout.status, 204);

    let revoked_list = app.handle(
        HttpRequest::new("GET", "/api/collections/posts/records")
            .with_header("Authorization", format!("Bearer {revoked_token}")),
    );
    assert_eq!(revoked_list.status, 200);
    assert_eq!(revoked_list.body["totalItems"], 0);
    outcomes.insert(
        "revoked auth token becomes empty rule auth context".to_string(),
        FixtureOutcome::from_response(&revoked_list),
    );

    let revoked_refresh = app.handle(
        HttpRequest::new("POST", "/api/collections/users/auth-refresh")
            .with_header("Authorization", format!("Bearer {revoked_token}")),
    );
    outcomes.insert(
        "revoked auth token cannot refresh".to_string(),
        FixtureOutcome::from_response(&revoked_refresh),
    );

    outcomes
}

fn run_view_collection_fixture() -> BTreeMap<String, FixtureOutcome> {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());
    let mut outcomes = BTreeMap::new();

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
    assert_eq!(created_view.body["type"], "view");
    assert_eq!(created_view.body["viewQuery"], view_query);
    outcomes.insert(
        "view collection stores select query metadata".to_string(),
        FixtureOutcome::from_response(&created_view),
    );

    let list = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/published_posts/records?filter=title%20~%20%27Rusty%27",
    ));
    assert_eq!(list.status, 200);
    assert_eq!(list.body["totalItems"], 1);
    assert_eq!(list.body["items"][0]["id"], "post_1");
    assert_eq!(list.body["items"][0]["collectionName"], "published_posts");
    outcomes.insert(
        "view list applies filters over projected columns".to_string(),
        FixtureOutcome::from_response(&list),
    );

    let hidden = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/published_posts/records/post_2",
    ));
    outcomes.insert(
        "view get hides rows outside the query".to_string(),
        FixtureOutcome::from_response(&hidden),
    );

    let create_denied = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/published_posts/records",
            json!({"id": "post_3", "title": "Nope"}),
        )
        .unwrap(),
    );
    outcomes.insert(
        "view record create is rejected".to_string(),
        FixtureOutcome::from_response(&create_denied),
    );

    let patch_denied = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/published_posts/records/post_1",
            json!({"title": "Nope"}),
        )
        .unwrap(),
    );
    outcomes.insert(
        "view record update is rejected".to_string(),
        FixtureOutcome::from_response(&patch_denied),
    );

    let delete_denied = app.handle(HttpRequest::new(
        "DELETE",
        "/api/collections/published_posts/records/post_1",
    ));
    outcomes.insert(
        "view record delete is rejected".to_string(),
        FixtureOutcome::from_response(&delete_denied),
    );

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
    outcomes.insert(
        "view export includes view query".to_string(),
        FixtureOutcome::from_response(&exported),
    );

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
    outcomes.insert(
        "non-select view query is rejected".to_string(),
        FixtureOutcome::from_response(&invalid_view),
    );

    let internal_view = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "bad_auth_tokens_view",
                "type": "view",
                "viewQuery": "SELECT token AS id FROM \"_rb_auth_tokens\"",
                "fields": []
            }),
        )
        .unwrap(),
    );
    outcomes.insert(
        "view query cannot read internal auth tables".to_string(),
        FixtureOutcome::from_response(&internal_view),
    );

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
    outcomes.insert(
        "unsafe view function is blocked at execution".to_string(),
        FixtureOutcome::from_response(&unsafe_function_list),
    );

    outcomes
}

fn run_relation_expand_fixture() -> BTreeMap<String, FixtureOutcome> {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());
    let mut outcomes = BTreeMap::new();

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
                    "name": "author",
                    "kind": "relation",
                    "collection": "authors",
                    "maxSelect": 1
                },
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
        ("profiles", json!({"id": "profile_1", "bio": "Rust writer"})),
        (
            "authors",
            json!({"id": "author_1", "name": "Ada", "profile": "profile_1"}),
        ),
        (
            "tags",
            json!({"id": "tag_rust", "label": "rust", "public": true}),
        ),
        (
            "tags",
            json!({"id": "tag_sqlite", "label": "sqlite", "public": true}),
        ),
        (
            "tags",
            json!({"id": "tag_private", "label": "draft", "public": false}),
        ),
        (
            "posts",
            json!({
                "id": "post_1",
                "title": "Rusty Base",
                "author": "author_1",
                "primaryTag": "tag_private",
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

    let expanded_list = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts/records?expand=author.profile,tags",
    ));
    assert_eq!(expanded_list.status, 200);
    assert_eq!(
        expanded_list.body["items"][0]["expand"]["author"]["expand"]["profile"]["bio"],
        "Rust writer"
    );
    outcomes.insert(
        "list expands single nested relation".to_string(),
        FixtureOutcome::from_response(&expanded_list),
    );
    assert_eq!(
        expanded_list.body["items"][0]["expand"]["tags"][0]["label"],
        "rust"
    );
    assert_eq!(
        expanded_list.body["items"][0]["expand"]["tags"][1]["label"],
        "sqlite"
    );
    outcomes.insert(
        "list expands multi relation in stored order".to_string(),
        FixtureOutcome::from_response(&expanded_list),
    );

    let expanded_record = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts/records/post_1?expand=author,tags",
    ));
    assert_eq!(expanded_record.status, 200);
    assert_eq!(
        expanded_record.body["expand"]["author"]["collectionName"],
        "authors"
    );
    assert_eq!(
        expanded_record.body["expand"]["tags"][0]["collectionName"],
        "tags"
    );
    outcomes.insert(
        "record expand includes collection metadata".to_string(),
        FixtureOutcome::from_response(&expanded_record),
    );

    let projected = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts/records?expand=author.profile,tags&fields=*,expand.author.name,expand.tags.label",
    ));
    assert_eq!(projected.status, 200);
    assert_eq!(
        projected.body["items"][0]["expand"]["author"]["name"],
        "Ada"
    );
    assert!(projected.body["items"][0]["expand"]["author"]
        .get("collectionName")
        .is_none());
    assert!(projected.body["items"][0]["expand"]["author"]
        .get("expand")
        .is_none());
    assert_eq!(
        projected.body["items"][0]["expand"]["tags"][0]["label"],
        "rust"
    );
    assert!(projected.body["items"][0]["expand"]["tags"][0]
        .get("id")
        .is_none());
    outcomes.insert(
        "projected expand keeps only requested fields".to_string(),
        FixtureOutcome::from_response(&projected),
    );

    let blocked = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts/records/post_1?expand=primaryTag,tags",
    ));
    assert_eq!(blocked.status, 200);
    assert!(blocked.body["expand"].get("primaryTag").is_none());
    assert_eq!(blocked.body["expand"]["tags"].as_array().unwrap().len(), 2);
    outcomes.insert(
        "blocked relation expand is omitted".to_string(),
        FixtureOutcome::from_response(&blocked),
    );

    outcomes
}

fn run_protected_file_fixture() -> BTreeMap<String, FixtureOutcome> {
    let path = temp_db_path("pocketbase-protected-file-fixture");
    let app = RustyBaseApp::new(Store::open(&path).unwrap());
    let mut outcomes = BTreeMap::new();

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

    let created = app.handle(multipart_request(
        "POST",
        "/api/collections/docs/records",
        "rb-server-fixture-boundary",
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
    outcomes.insert(
        "protected file without token is hidden".to_string(),
        FixtureOutcome::from_response(&without_token),
    );

    let missing_auth = app.handle(HttpRequest::new("POST", "/api/files/token"));
    outcomes.insert(
        "file token request requires auth".to_string(),
        FixtureOutcome::from_response(&missing_auth),
    );

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
        HttpRequest::new("POST", "/api/files/token")
            .with_header("Authorization", format!("Bearer {owner_auth_token}")),
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
    assert_eq!(allowed.content_type, "application/pdf");
    assert_eq!(allowed.raw_body, b"contract bytes");
    outcomes.insert(
        "owner file token allows download".to_string(),
        FixtureOutcome::from_response(&allowed),
    );

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
    outcomes.insert(
        "expired file token is rejected".to_string(),
        FixtureOutcome::from_response(&expired),
    );

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
    outcomes.insert(
        "other user file token is hidden by record rule".to_string(),
        FixtureOutcome::from_response(&denied),
    );

    drop(app);
    fs::remove_file(path).ok();

    outcomes
}

fn run_realtime_fixture() -> BTreeMap<String, FixtureOutcome> {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());
    let mut outcomes = BTreeMap::new();

    let connect_response = app.handle(HttpRequest::new("GET", "/api/realtime"));
    assert_eq!(connect_response.content_type, "text/event-stream");
    assert!(String::from_utf8(connect_response.raw_body.clone())
        .unwrap()
        .contains("event: PB_CONNECT"));
    outcomes.insert(
        "realtime connect returns PB_CONNECT".to_string(),
        FixtureOutcome::from_response(&connect_response),
    );

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

    let owner_token = login_token(&app, "owner@example.com");
    let other_token = login_token(&app, "other@example.com");

    let posts = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "title", "type": "text"},
                    {"name": "owner", "type": "text"}
                ],
                "listRule": "owner = @request.auth.id",
                "viewRule": "owner = @request.auth.id"
            }),
        )
        .unwrap(),
    );
    assert_eq!(posts.status, 200);

    let invalid_client = app.handle(
        HttpRequest::json(
            "POST",
            "/api/realtime",
            json!({"clientId": "missing", "subscriptions": ["posts/*"]}),
        )
        .unwrap(),
    );
    outcomes.insert(
        "invalid realtime client is rejected".to_string(),
        FixtureOutcome::from_response(&invalid_client),
    );

    let owner_list = app.realtime_connect().unwrap();
    assert_connect_event(&owner_list);
    let owner_record = app.realtime_connect().unwrap();
    assert_connect_event(&owner_record);
    let anonymous_list = app.realtime_connect().unwrap();
    assert_connect_event(&anonymous_list);
    let other_list = app.realtime_connect().unwrap();
    assert_connect_event(&other_list);

    let owner_subscribe = app.handle(
        HttpRequest::json(
            "POST",
            "/api/realtime",
            json!({"clientId": owner_list.client_id, "subscriptions": ["posts/*"]}),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {owner_token}")),
    );
    outcomes.insert(
        "owner realtime subscription is accepted".to_string(),
        FixtureOutcome::from_response(&owner_subscribe),
    );

    let record_subscribe = app.handle(
        HttpRequest::json(
            "POST",
            "/api/realtime",
            json!({"clientId": owner_record.client_id, "subscriptions": ["posts/post_owner"]}),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {owner_token}")),
    );
    outcomes.insert(
        "record-specific realtime subscription is accepted".to_string(),
        FixtureOutcome::from_response(&record_subscribe),
    );

    let anonymous_subscribe = app.handle(
        HttpRequest::json(
            "POST",
            "/api/realtime",
            json!({"clientId": anonymous_list.client_id, "subscriptions": ["posts/*"]}),
        )
        .unwrap(),
    );
    outcomes.insert(
        "anonymous realtime subscription is accepted with empty auth context".to_string(),
        FixtureOutcome::from_response(&anonymous_subscribe),
    );

    let other_subscribe = app.handle(
        HttpRequest::json(
            "POST",
            "/api/realtime",
            json!({"clientId": other_list.client_id, "subscriptions": ["posts/*"]}),
        )
        .unwrap()
        .with_header("Authorization", format!("Bearer {other_token}")),
    );
    assert_eq!(other_subscribe.status, 204);

    let owner_create = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"id": "post_owner", "title": "Owner post", "owner": "user_1"}),
        )
        .unwrap(),
    );
    assert_realtime_record_event(&owner_list, "posts/*", "create", "post_owner");
    assert_realtime_record_event(&owner_record, "posts/post_owner", "create", "post_owner");
    assert_no_realtime_event(&anonymous_list);
    assert_no_realtime_event(&other_list);
    outcomes.insert(
        "owner record create event is delivered to matching subscribers".to_string(),
        FixtureOutcome::from_response(&owner_create),
    );

    let other_create = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({"id": "post_other", "title": "Other post", "owner": "user_2"}),
        )
        .unwrap(),
    );
    assert_realtime_record_event(&other_list, "posts/*", "create", "post_other");
    assert_no_realtime_event(&owner_list);
    assert_no_realtime_event(&owner_record);
    assert_no_realtime_event(&anonymous_list);
    outcomes.insert(
        "non-matching auth context does not receive realtime event".to_string(),
        FixtureOutcome::from_response(&other_create),
    );

    let owner_update = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/collections/posts/records/post_owner",
            json!({"title": "Owner post updated"}),
        )
        .unwrap(),
    );
    assert_realtime_record_event(&owner_list, "posts/*", "update", "post_owner");
    assert_realtime_record_event(&owner_record, "posts/post_owner", "update", "post_owner");
    outcomes.insert(
        "owner record update event is delivered".to_string(),
        FixtureOutcome::from_response(&owner_update),
    );

    let owner_delete = app.handle(HttpRequest::new(
        "DELETE",
        "/api/collections/posts/records/post_owner",
    ));
    assert_realtime_record_event(&owner_list, "posts/*", "delete", "post_owner");
    assert_realtime_record_event(&owner_record, "posts/post_owner", "delete", "post_owner");
    outcomes.insert(
        "owner record delete event is delivered before removal".to_string(),
        FixtureOutcome::from_response(&owner_delete),
    );

    outcomes
}

fn run_batch_fixture() -> BTreeMap<String, FixtureOutcome> {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());
    let mut outcomes = BTreeMap::new();

    let posts = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"name": "title", "type": "text", "required": true},
                    {"name": "owner", "type": "text"},
                    {"name": "published", "type": "bool"}
                ],
                "createRule": "@request.body.owner = @request.auth.id",
                "updateRule": "owner = @request.auth.id",
                "deleteRule": "owner = @request.auth.id"
            }),
        )
        .unwrap(),
    );
    assert_eq!(posts.status, 200);

    let empty = app.handle(
        HttpRequest::json("POST", "/api/batch", json!({"requests": []}))
            .unwrap()
            .with_header("x-rb-auth-id", "user_1"),
    );
    assert_eq!(empty.body.as_array().unwrap().len(), 0);
    outcomes.insert(
        "empty batch returns an empty response list".to_string(),
        FixtureOutcome::from_response(&empty),
    );

    let success = app.handle(
        HttpRequest::json(
            "POST",
            "/api/batch",
            json!({
                "requests": [
                    {
                        "method": "POST",
                        "url": "/api/collections/posts/records",
                        "body": {
                            "id": "post_1",
                            "title": "One",
                            "owner": "user_1",
                            "published": true
                        }
                    },
                    {
                        "method": "POST",
                        "url": "/api/collections/posts/records",
                        "body": {
                            "id": "post_2",
                            "title": "Two",
                            "owner": "user_1",
                            "published": false
                        }
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
        .unwrap()
        .with_header("x-rb-auth-id", "user_1"),
    );
    assert_eq!(success.body.as_array().unwrap().len(), 4);
    assert_eq!(success.body[0]["status"], 200);
    assert_eq!(success.body[1]["status"], 200);
    assert_eq!(success.body[2]["status"], 200);
    assert_eq!(success.body[3]["status"], 204);
    assert_eq!(success.body[2]["body"]["title"], "One Updated");
    outcomes.insert(
        "successful batch commits all child record mutations".to_string(),
        FixtureOutcome::from_response(&success),
    );

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

    let forwarded_auth = app.handle(
        HttpRequest::json(
            "POST",
            "/api/batch",
            json!({
                "requests": [
                    {
                        "method": "POST",
                        "url": "/api/collections/posts/records",
                        "body": {
                            "id": "post_auth",
                            "title": "Auth context",
                            "owner": "user_1",
                            "published": true
                        }
                    }
                ]
            }),
        )
        .unwrap()
        .with_header("x-rb-auth-id", "user_1"),
    );
    assert_eq!(forwarded_auth.body[0]["body"]["owner"], "user_1");
    outcomes.insert(
        "parent auth context is forwarded to child requests".to_string(),
        FixtureOutcome::from_response(&forwarded_auth),
    );

    let upsert_create = app.handle(
        HttpRequest::json(
            "POST",
            "/api/batch",
            json!({
                "requests": [
                    {
                        "method": "PUT",
                        "url": "/api/collections/posts/records",
                        "body": {
                            "id": "post_upsert",
                            "title": "Upsert created",
                            "owner": "user_1",
                            "published": false
                        }
                    }
                ]
            }),
        )
        .unwrap()
        .with_header("x-rb-auth-id", "user_1"),
    );
    assert_eq!(upsert_create.body[0]["status"], 200);
    assert_eq!(upsert_create.body[0]["body"]["title"], "Upsert created");
    outcomes.insert(
        "upsert batch creates a missing record".to_string(),
        FixtureOutcome::from_response(&upsert_create),
    );

    let upsert_update = app.handle(
        HttpRequest::json(
            "POST",
            "/api/batch",
            json!({
                "requests": [
                    {
                        "method": "PUT",
                        "url": "/api/collections/posts/records",
                        "body": {
                            "id": "post_upsert",
                            "title": "Upsert updated",
                            "owner": "user_1",
                            "published": true
                        }
                    }
                ]
            }),
        )
        .unwrap()
        .with_header("x-rb-auth-id", "user_1"),
    );
    assert_eq!(upsert_update.body[0]["status"], 200);
    assert_eq!(upsert_update.body[0]["body"]["title"], "Upsert updated");
    outcomes.insert(
        "upsert batch updates an existing record".to_string(),
        FixtureOutcome::from_response(&upsert_update),
    );

    let failed = app.handle(
        HttpRequest::json(
            "POST",
            "/api/batch",
            json!({
                "requests": [
                    {
                        "method": "POST",
                        "url": "/api/collections/posts/records",
                        "body": {
                            "id": "post_rollback",
                            "title": "Rollback",
                            "owner": "user_1",
                            "published": true
                        }
                    },
                    {
                        "method": "PATCH",
                        "url": "/api/collections/posts/records/missing",
                        "body": {"title": "Missing"}
                    }
                ]
            }),
        )
        .unwrap()
        .with_header("x-rb-auth-id", "user_1"),
    );
    assert_eq!(failed.body["message"], "Batch transaction failed.");
    assert_eq!(
        failed.body["data"]["requests"]["1"]["response"]["status"],
        404
    );
    let rolled_back = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/posts/records/post_rollback",
    ));
    assert_eq!(rolled_back.status, 404);
    outcomes.insert(
        "failed child rolls back earlier child mutations".to_string(),
        FixtureOutcome::from_response(&failed)
            .with_code(json_string(&failed, &["data", "requests", "1", "code"])),
    );

    let unsupported = app.handle(
        HttpRequest::json(
            "POST",
            "/api/batch",
            json!({
                "requests": [
                    {
                        "method": "GET",
                        "url": "/api/collections/posts/records"
                    }
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(
        unsupported.body["data"]["requests"]["0"]["response"]["status"],
        400
    );
    outcomes.insert(
        "unsupported child request fails the batch".to_string(),
        FixtureOutcome::from_response(&unsupported).with_code(json_string(
            &unsupported,
            &["data", "requests", "0", "code"],
        )),
    );

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
                        "body": {
                            "id": "post_custom_auth",
                            "title": "Custom Auth",
                            "owner": "user_1"
                        }
                    }
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(
        custom_auth.body["data"]["requests"]["0"]["response"]["status"],
        400
    );
    outcomes.insert(
        "custom child auth header fails the batch".to_string(),
        FixtureOutcome::from_response(&custom_auth).with_code(json_string(
            &custom_auth,
            &["data", "requests", "0", "code"],
        )),
    );

    let limited = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/settings",
            json!({"batch": {"maxRequests": 1}}),
        )
        .unwrap(),
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
                        "body": {"id": "post_limit_1", "title": "One", "owner": "user_1"}
                    },
                    {
                        "method": "POST",
                        "url": "/api/collections/posts/records",
                        "body": {"id": "post_limit_2", "title": "Two", "owner": "user_1"}
                    }
                ]
            }),
        )
        .unwrap()
        .with_header("x-rb-auth-id", "user_1"),
    );
    outcomes.insert(
        "maxRequests setting rejects oversized batches".to_string(),
        FixtureOutcome::from_response(&too_many)
            .with_code(json_string(&too_many, &["data", "requests", "code"])),
    );

    let disabled = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/settings",
            json!({"batch": {"enabled": false, "maxRequests": 50}}),
        )
        .unwrap(),
    );
    assert_eq!(disabled.status, 200);
    let disabled_batch =
        app.handle(HttpRequest::json("POST", "/api/batch", json!({"requests": []})).unwrap());
    assert_eq!(disabled_batch.body["message"], "Batch API is disabled.");
    outcomes.insert(
        "disabled batch setting rejects requests".to_string(),
        FixtureOutcome::from_response(&disabled_batch),
    );

    outcomes
}

fn run_import_export_fixture() -> BTreeMap<String, FixtureOutcome> {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());
    let mut outcomes = BTreeMap::new();

    let posts = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections",
            json!({
                "name": "posts",
                "fields": [
                    {"id": "title_field", "name": "title", "type": "text", "required": true},
                    {"name": "legacy", "type": "text"},
                    {"name": "published", "type": "bool"}
                ],
                "indexes": ["CREATE INDEX idx_posts_title ON posts (title)"],
                "listRule": "published = true"
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
                "fields": [{"name": "body", "type": "text"}]
            }),
        )
        .unwrap(),
    );
    assert_eq!(comments.status, 200);

    let created = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/posts/records",
            json!({
                "id": "post_1",
                "title": "Rusty Base",
                "legacy": "keep for merge",
                "published": true
            }),
        )
        .unwrap(),
    );
    assert_eq!(created.status, 200);

    let exported = app.handle(HttpRequest::new("GET", "/api/collections/meta/export"));
    assert_eq!(exported.status, 200);
    let exported_posts = collection_by_name(&exported.body, "posts");
    assert_eq!(exported_posts["type"], "base");
    assert_eq!(exported_posts["listRule"], "published = true");
    assert_eq!(
        exported_posts["indexes"],
        json!(["CREATE INDEX idx_posts_title ON posts (title)"])
    );
    assert_eq!(field_by_name(exported_posts, "title")["id"], "title_field");
    assert_eq!(field_by_name(exported_posts, "title")["type"], "text");
    assert!(field_by_name(exported_posts, "title").get("kind").is_none());
    outcomes.insert(
        "export payload preserves collection metadata".to_string(),
        FixtureOutcome::from_response(&exported),
    );

    let fresh = RustyBaseApp::new(Store::open_in_memory().unwrap());
    let fresh_import = fresh.handle(
        HttpRequest::json("PUT", "/api/collections/import", exported.body.clone()).unwrap(),
    );
    assert_eq!(fresh_import.status, 204);
    let fresh_posts = fresh.handle(HttpRequest::new("GET", "/api/collections/posts"));
    assert_eq!(fresh_posts.status, 200);
    assert_eq!(
        collection_field_by_name(&fresh_posts.body, "title")["id"],
        "title_field"
    );
    assert_eq!(
        fresh_posts.body["indexes"],
        json!(["CREATE INDEX idx_posts_title ON posts (title)"])
    );
    assert_eq!(fresh_posts.body["listRule"], "published = true");
    outcomes.insert(
        "export payload imports into a fresh app".to_string(),
        FixtureOutcome::from_response(&fresh_import),
    );

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
    assert_eq!(user_collection_fields(&posts_after_merge.body).len(), 4);
    assert_eq!(posts_after_merge.body["listRule"], "title ~ 'Rusty'");
    let records_after_merge = app.handle(HttpRequest::new("GET", "/api/collections/posts/records"));
    assert_eq!(records_after_merge.status, 200);
    assert_eq!(
        records_after_merge.body["items"][0]["legacy"],
        "keep for merge"
    );
    outcomes.insert(
        "merge import preserves omitted fields and records".to_string(),
        FixtureOutcome::from_response(&merge_import),
    );

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
    let records_after_replace =
        app.handle(HttpRequest::new("GET", "/api/collections/posts/records"));
    assert_eq!(records_after_replace.status, 200);
    assert_eq!(
        records_after_replace.body["items"][0]["title"],
        "Rusty Base"
    );
    assert!(records_after_replace.body["items"][0]
        .get("legacy")
        .is_none());
    let author = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/authors/records",
            json!({"id": "author_1", "name": "Ada"}),
        )
        .unwrap(),
    );
    assert_eq!(author.status, 200);
    outcomes.insert(
        "deleteMissing import replaces missing metadata and prunes record fields".to_string(),
        FixtureOutcome::from_response(&replace_import),
    );

    let array_app = RustyBaseApp::new(Store::open_in_memory().unwrap());
    let array_import = array_app.handle(
        HttpRequest::json(
            "PUT",
            "/api/collections/import",
            json!([
                {
                    "name": "array_posts",
                    "schema": [{"name": "title", "type": "text"}]
                }
            ]),
        )
        .unwrap(),
    );
    assert_eq!(array_import.status, 204);
    let array_posts = array_app.handle(HttpRequest::new("GET", "/api/collections/array_posts"));
    assert_eq!(array_posts.status, 200);
    outcomes.insert(
        "array root import payload is accepted".to_string(),
        FixtureOutcome::from_response(&array_import),
    );

    let duplicate_import = app.handle(
        HttpRequest::json(
            "PUT",
            "/api/collections/import",
            json!({
                "collections": [
                    {"name": "dupes", "schema": [{"name": "title", "type": "text"}]},
                    {"name": "dupes", "schema": [{"name": "body", "type": "text"}]}
                ]
            }),
        )
        .unwrap(),
    );
    assert_eq!(duplicate_import.status, 400);
    outcomes.insert(
        "duplicate collection names are rejected before import".to_string(),
        FixtureOutcome::from_response(&duplicate_import),
    );

    outcomes
}

fn run_settings_fixture() -> BTreeMap<String, FixtureOutcome> {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());
    let mut outcomes = BTreeMap::new();

    let public_defaults = app.handle(HttpRequest::new("GET", "/api/settings"));
    assert_eq!(public_defaults.body["meta"]["appName"], "Rusty Base");
    assert_eq!(public_defaults.body["batch"]["maxRequests"], 50);
    outcomes.insert(
        "settings defaults are readable before superuser bootstrap".to_string(),
        FixtureOutcome::from_response(&public_defaults),
    );

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
    outcomes.insert(
        "settings require superuser after bootstrap".to_string(),
        FixtureOutcome::from_response(&blocked),
    );

    let superuser_token = superuser_login_token(&app);
    let auth_header = format!("Bearer {superuser_token}");

    let patched = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/settings",
            json!({
                "meta": {
                    "appName": "Acme",
                    "appURL": "https://example.com",
                    "senderName": "Acme Ops",
                    "senderAddress": "noreply@example.com",
                    "hideControls": true
                },
                "logs": {
                    "maxDays": 14,
                    "minLevel": 1,
                    "logIp": false,
                    "logAuthId": true
                },
                "batch": {
                    "enabled": true,
                    "maxRequests": 2,
                    "timeout": 30,
                    "maxBodySize": 2048
                },
                "smtp": {
                    "enabled": true,
                    "host": "smtp.example.com",
                    "port": 2525,
                    "username": "mailer",
                    "password": "smtp-secret",
                    "authMethod": "plain",
                    "tls": false,
                    "localName": "rusty-base"
                },
                "s3": {
                    "enabled": true,
                    "bucket": "assets",
                    "region": "auto",
                    "endpoint": "https://s3.example.com",
                    "accessKey": "access",
                    "secret": "s3-secret",
                    "forcePathStyle": true
                },
                "backups": {
                    "cron": "0 3 * * *",
                    "cronMaxKeep": 7,
                    "s3": {
                        "enabled": true,
                        "bucket": "backups",
                        "region": "auto",
                        "endpoint": "https://s3.example.com",
                        "accessKey": "backup-access",
                        "secret": "backup-secret"
                    }
                },
                "rateLimits": {
                    "enabled": true,
                    "rules": [{
                        "label": "/api/custom",
                        "audience": "@request.auth.id",
                        "duration": 15,
                        "maxRequests": 4
                    }]
                },
                "trustedProxy": {
                    "headers": ["X-Forwarded-For", "CF-Connecting-IP"],
                    "useLeftmostIp": true
                }
            }),
        )
        .unwrap()
        .with_header("Authorization", auth_header.clone()),
    );
    assert_eq!(patched.body["meta"]["appName"], "Acme");
    assert_eq!(patched.body["meta"]["appURL"], "https://example.com");
    assert_eq!(patched.body["batch"]["maxRequests"], 2);
    assert_eq!(patched.body["smtp"]["password"], "******");
    assert_eq!(patched.body["s3"]["secret"], "******");
    assert_eq!(patched.body["backups"]["s3"]["secret"], "******");
    assert_eq!(
        patched.body["rateLimits"]["rules"][0]["label"],
        "/api/custom"
    );
    assert_eq!(patched.body["trustedProxy"]["useLeftmostIp"], true);
    outcomes.insert(
        "superuser patch updates settings and redacts secrets".to_string(),
        FixtureOutcome::from_response(&patched),
    );

    let redacted_patch = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/settings?fields=smtp.password,s3.secret,backups.s3.secret,batch.maxRequests",
            json!({
                "smtp": {"password": "******"},
                "s3": {"secret": "******"},
                "backups": {"s3": {"secret": "******"}},
                "batch": {"maxRequests": 3}
            }),
        )
        .unwrap()
        .with_header("Authorization", auth_header.clone()),
    );
    assert_eq!(redacted_patch.body["smtp"]["password"], "******");
    assert_eq!(redacted_patch.body["s3"]["secret"], "******");
    assert_eq!(redacted_patch.body["backups"]["s3"]["secret"], "******");
    assert_eq!(redacted_patch.body["batch"]["maxRequests"], 3);
    let stored_settings = app.store().get_settings().unwrap();
    assert_eq!(stored_settings.smtp.password, "smtp-secret");
    assert_eq!(stored_settings.s3.secret, "s3-secret");
    assert_eq!(stored_settings.backups.s3.secret, "backup-secret");
    outcomes.insert(
        "redacted secret placeholders preserve stored secrets".to_string(),
        FixtureOutcome::from_response(&redacted_patch),
    );

    let projected = app.handle(
        HttpRequest::new(
            "GET",
            "/api/settings?fields=meta.appName,batch.maxRequests,smtp.password",
        )
        .with_header("Authorization", auth_header.clone()),
    );
    assert_eq!(projected.body["meta"]["appName"], "Acme");
    assert_eq!(projected.body["batch"]["maxRequests"], 3);
    assert_eq!(projected.body["smtp"]["password"], "******");
    assert!(projected.body.get("s3").is_none());
    outcomes.insert(
        "settings fields projection returns selected settings".to_string(),
        FixtureOutcome::from_response(&projected),
    );

    let invalid_batch = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/settings",
            json!({"batch": {"maxRequests": 0}}),
        )
        .unwrap()
        .with_header("Authorization", auth_header.clone()),
    );
    outcomes.insert(
        "invalid batch settings return field validation errors".to_string(),
        FixtureOutcome::from_response(&invalid_batch).with_code(json_string(
            &invalid_batch,
            &["data", "batch.maxRequests", "code"],
        )),
    );

    let invalid_backup = app.handle(
        HttpRequest::json(
            "PATCH",
            "/api/settings",
            json!({"backups": {"s3": {"enabled": true, "secret": ""}}}),
        )
        .unwrap()
        .with_header("Authorization", auth_header),
    );
    outcomes.insert(
        "enabled backup s3 settings require a secret".to_string(),
        FixtureOutcome::from_response(&invalid_backup).with_code(json_string(
            &invalid_backup,
            &["data", "backups.s3.secret", "code"],
        )),
    );

    outcomes
}

fn login_token(app: &RustyBaseApp, identity: &str) -> String {
    let login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/users/auth-with-password",
            json!({"identity": identity, "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(login.status, 200);
    login.body["token"].as_str().unwrap().to_string()
}

fn superuser_login_token(app: &RustyBaseApp) -> String {
    let login = app.handle(
        HttpRequest::json(
            "POST",
            "/api/collections/_superusers/auth-with-password",
            json!({"identity": "root@example.com", "password": "correct horse"}),
        )
        .unwrap(),
    );
    assert_eq!(login.status, 200);
    login.body["token"].as_str().unwrap().to_string()
}

fn assert_connect_event(connection: &RealtimeConnection) {
    let event = expect_realtime_event(connection);
    assert_eq!(event.event, "PB_CONNECT");
    assert_eq!(event.data["clientId"], connection.client_id);
}

fn assert_realtime_record_event(
    connection: &RealtimeConnection,
    topic: &str,
    action: &str,
    id: &str,
) {
    let event = expect_realtime_event(connection);
    assert_eq!(event.event, topic);
    assert_eq!(event.data["action"], action);
    assert_eq!(event.data["record"]["id"], id);
}

fn assert_no_realtime_event(connection: &RealtimeConnection) {
    assert!(connection.recv_timeout(Duration::from_millis(50)).is_err());
}

fn expect_realtime_event(connection: &RealtimeConnection) -> RealtimeEvent {
    connection.recv_timeout(Duration::from_millis(200)).unwrap()
}

fn json_string(response: &HttpResponse, path: &[&str]) -> String {
    let mut value = &response.body;
    for part in path {
        value = value.get(*part).unwrap_or_else(|| {
            panic!("missing response JSON path {path:?} in {:?}", response.body)
        });
    }
    value
        .as_str()
        .unwrap_or_else(|| panic!("response JSON path {path:?} is not a string"))
        .to_string()
}

fn collection_by_name<'a>(payload: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    payload["collections"]
        .as_array()
        .unwrap_or_else(|| panic!("payload has no collections array: {payload:?}"))
        .iter()
        .find(|collection| collection["name"] == name)
        .unwrap_or_else(|| panic!("missing collection {name} in payload: {payload:?}"))
}

fn field_by_name<'a>(collection: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    collection["schema"]
        .as_array()
        .unwrap_or_else(|| panic!("collection has no schema array: {collection:?}"))
        .iter()
        .find(|field| field["name"] == name)
        .unwrap_or_else(|| panic!("missing field {name} in collection: {collection:?}"))
}

fn collection_field_by_name<'a>(
    collection: &'a serde_json::Value,
    name: &str,
) -> &'a serde_json::Value {
    user_collection_fields(collection)
        .into_iter()
        .find(|field| field["name"] == name)
        .unwrap_or_else(|| panic!("missing field {name} in collection response: {collection:?}"))
}

fn user_collection_fields(collection: &serde_json::Value) -> Vec<&serde_json::Value> {
    collection["fields"]
        .as_array()
        .unwrap_or_else(|| panic!("collection has no fields array: {collection:?}"))
        .iter()
        .filter(|field| !matches!(field["name"].as_str(), Some("id" | "created" | "updated")))
        .collect()
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
