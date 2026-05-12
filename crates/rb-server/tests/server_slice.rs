use rb_filter_engine::{FilterContext, Value as FilterValue};
use rb_server::{
    CollectionConfig, CollectionField, CollectionFieldKind, HttpRequest, ListOptions, RustyBaseApp,
    Store,
};
use serde_json::json;

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
