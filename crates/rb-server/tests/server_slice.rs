use rb_filter_engine::{FilterContext, Value as FilterValue};
use rb_server::{
    CollectionConfig, CollectionField, CollectionFieldKind, HttpRequest, ListOptions, RustyBaseApp,
    Store,
};
use rusqlite::{params, Connection};
use serde_json::json;
use std::{
    env, fs,
    path::PathBuf,
    process,
    time::{SystemTime, UNIX_EPOCH},
};

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
    assert_eq!(logged_out.status, 403);
    assert!(logged_out.body["message"]
        .as_str()
        .unwrap()
        .contains("invalid auth token"));

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
    assert_eq!(expired.status, 403);
    assert!(expired.body["message"]
        .as_str()
        .unwrap()
        .contains("expired auth token"));
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
                "listRule": "title ~ 'Rusty'"
            }),
        )
        .unwrap(),
    );
    assert_eq!(patched.status, 200);
    assert_eq!(patched.body["name"], "articles");
    assert_eq!(patched.body["fields"].as_array().unwrap().len(), 2);

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
