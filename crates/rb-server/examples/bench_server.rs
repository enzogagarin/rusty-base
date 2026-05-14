use rb_server::{HttpRequest, HttpResponse, RustyBaseApp, Store};
use serde_json::{json, Value as JsonValue};
use std::{
    hint::black_box,
    io::Cursor,
    time::{Duration, Instant},
};

const RECORD_COUNT: usize = 500;
const LIST_ITERATIONS: usize = 500;
const EXPAND_ITERATIONS: usize = 250;
const VIEW_ITERATIONS: usize = 500;
const THUMB_ITERATIONS: usize = 100;

fn main() {
    let (app, thumbnail_path) = seeded_app();

    println!("rb-server HTTP benchmark");
    println!("records: {RECORD_COUNT}");
    print_result(
        "list filter",
        bench_get(
            &app,
            "/api/collections/posts/records?filter=published%20%3D%20true%20%26%26%20score%20%3E%3D%2020&perPage=100",
            LIST_ITERATIONS,
        ),
        LIST_ITERATIONS,
    );
    print_result(
        "relation expand",
        bench_get(
            &app,
            "/api/collections/posts/records?expand=author,tags&perPage=50&skipTotal=1",
            EXPAND_ITERATIONS,
        ),
        EXPAND_ITERATIONS,
    );
    print_result(
        "view query list",
        bench_get(
            &app,
            "/api/collections/published_posts/records?filter=score%20%3E%3D%2020&perPage=100",
            VIEW_ITERATIONS,
        ),
        VIEW_ITERATIONS,
    );
    print_result(
        "thumbnail",
        bench_get(&app, &thumbnail_path, THUMB_ITERATIONS),
        THUMB_ITERATIONS,
    );
}

fn bench_get(app: &RustyBaseApp, path: &str, iterations: usize) -> Duration {
    for _ in 0..10 {
        let response = app.handle(HttpRequest::new("GET", path));
        assert_ok(path, &response);
        black_box(response);
    }

    let start = Instant::now();
    for _ in 0..iterations {
        let response = app.handle(HttpRequest::new("GET", path));
        assert_ok(path, &response);
        black_box(response);
    }
    start.elapsed()
}

fn print_result(name: &str, elapsed: Duration, iterations: usize) {
    let nanos = elapsed.as_nanos() / iterations as u128;
    println!("{name:<18} {nanos:>10} ns/iter");
}

fn seeded_app() -> (RustyBaseApp, String) {
    let app = RustyBaseApp::new(Store::open_in_memory().unwrap());

    create_collection(
        &app,
        json!({
            "name": "authors",
            "fields": [{"name": "name", "type": "text"}]
        }),
    );
    create_collection(
        &app,
        json!({
            "name": "tags",
            "fields": [{"name": "label", "type": "text"}]
        }),
    );
    create_collection(
        &app,
        json!({
            "name": "posts",
            "fields": [
                {"name": "title", "type": "text"},
                {"name": "published", "type": "bool"},
                {"name": "score", "type": "number"},
                {
                    "name": "author",
                    "type": "relation",
                    "collection": "authors",
                    "maxSelect": 1
                },
                {
                    "name": "tags",
                    "type": "relation",
                    "collection": "tags",
                    "maxSelect": 5
                }
            ]
        }),
    );

    for index in 0..10 {
        post_json(
            &app,
            "/api/collections/authors/records",
            json!({
                "id": format!("author_{index}"),
                "name": format!("Author {index}")
            }),
        );
    }
    for index in 0..20 {
        post_json(
            &app,
            "/api/collections/tags/records",
            json!({
                "id": format!("tag_{index}"),
                "label": format!("tag-{index}")
            }),
        );
    }
    for index in 0..RECORD_COUNT {
        post_json(
            &app,
            "/api/collections/posts/records",
            json!({
                "id": format!("post_{index}"),
                "title": format!("Post {index}"),
                "published": index % 3 != 0,
                "score": index % 100,
                "author": format!("author_{}", index % 10),
                "tags": [
                    format!("tag_{}", index % 20),
                    format!("tag_{}", (index + 1) % 20),
                    format!("tag_{}", (index + 2) % 20)
                ]
            }),
        );
    }

    create_collection(
        &app,
        json!({
            "name": "published_posts",
            "type": "view",
            "viewQuery": "SELECT id, json_extract(data, '$.title') AS title, json_extract(data, '$.score') AS score, created, updated FROM \"_rb_records_posts\" WHERE json_extract(data, '$.published') = 1",
            "fields": [
                {"name": "title", "type": "text"},
                {"name": "score", "type": "number"}
            ]
        }),
    );

    let thumbnail_path = seed_thumbnail_fixture(&app);
    (app, thumbnail_path)
}

fn create_collection(app: &RustyBaseApp, body: JsonValue) {
    let response = post_json(app, "/api/collections", body);
    assert_ok("create collection", &response);
}

fn post_json(app: &RustyBaseApp, path: &str, body: JsonValue) -> HttpResponse {
    let response = app.handle(HttpRequest::json("POST", path, body).unwrap());
    assert_ok(path, &response);
    response
}

fn assert_ok(label: &str, response: &HttpResponse) {
    assert!(
        response.status < 400,
        "{label} returned {}: {:?}",
        response.status,
        response.body
    );
}

fn seed_thumbnail_fixture(app: &RustyBaseApp) -> String {
    create_collection(
        app,
        json!({
            "name": "images",
            "fields": [
                {"name": "public", "type": "bool"},
                {
                    "name": "photo",
                    "type": "file",
                    "maxSelect": 1,
                    "maxSize": 100000,
                    "mimeTypes": ["image/png"],
                    "thumbs": ["64x64f"]
                }
            ],
            "viewRule": "public = true"
        }),
    );

    let created = app.handle(multipart_request(
        "POST",
        "/api/collections/images/records",
        "rb-bench-image-boundary",
        vec![
            multipart_field("id", "image_1"),
            multipart_field("public", "true"),
            multipart_file_bytes("photo", "photo.png", "image/png", png_fixture(128, 64)),
        ],
    ));
    assert_ok("create image record", &created);
    let photo = created.body["photo"].as_str().unwrap();
    format!("/api/files/images/image_1/{photo}?thumb=64x64f")
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
        let red = (x * 2).min(255) as u8;
        let green = (y * 4).min(255) as u8;
        *pixel = image::Rgba([red, green, 180, 255]);
    }

    let mut output = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image)
        .write_to(&mut output, image::ImageFormat::Png)
        .unwrap();
    output.into_inner()
}
