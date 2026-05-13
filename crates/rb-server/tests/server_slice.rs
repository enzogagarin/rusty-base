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
    assert_eq!(users.body["fields"][0]["kind"], "email");

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
    assert_eq!(methods.body["mfa"]["enabled"], false);
    assert_eq!(methods.body["otp"]["duration"], 0);

    let projected = app.handle(HttpRequest::new(
        "GET",
        "/api/collections/users/auth-methods?fields=password.identityFields,otp.enabled",
    ));
    assert_eq!(projected.status, 200);
    assert_eq!(
        projected.body["password"]["identityFields"],
        json!(["email", "username"])
    );
    assert_eq!(projected.body["otp"]["enabled"], false);
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

    let blocked = app.handle(HttpRequest::new(
        "GET",
        format!("/api/files/docs/doc_1/{updated_attachment}"),
    ));
    assert_eq!(blocked.status, 404);
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
    assert_eq!(
        posts_after_merge.body["fields"].as_array().unwrap().len(),
        3
    );
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
    assert_eq!(
        posts_after_replace.body["fields"].as_array().unwrap().len(),
        2
    );

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
                "listRule": "published = true"
            }),
        )
        .unwrap(),
    );
    assert_eq!(created.status, 200);

    let exported = app.handle(HttpRequest::new("GET", "/api/collections/meta/export"));
    assert_eq!(exported.status, 200);
    assert_eq!(exported.body["collections"][0]["name"], "posts");
    assert_eq!(
        exported.body["collections"][0]["schema"][0]["name"],
        "title"
    );
    assert_eq!(exported.body["collections"][0]["schema"][0]["type"], "text");
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
    assert_eq!(imported_posts.body["fields"].as_array().unwrap().len(), 2);
    assert_eq!(imported_posts.body["listRule"], "published = true");
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
                &format!("/api/collections/{collection}/records"),
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
                &format!("/api/collections/{collection}/records"),
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
