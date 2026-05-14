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
