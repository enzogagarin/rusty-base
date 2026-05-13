use super::*;
use super::{app::*, realtime::*, storage::*, validation::*};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    pub fn json(
        method: impl Into<String>,
        path: impl Into<String>,
        body: impl Serialize,
    ) -> Result<Self, ServerError> {
        let mut request = Self::new(method, path);
        request
            .headers
            .insert("content-type".to_string(), "application/json".to_string());
        request.body = serde_json::to_vec(&body)?;
        Ok(request)
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        self.headers
            .insert(normalize_http_header_name(&name), value.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: JsonValue,
    pub content_type: String,
    pub headers: HashMap<String, String>,
    pub raw_body: Vec<u8>,
}

impl HttpResponse {
    pub fn json(status: u16, body: JsonValue) -> Self {
        Self {
            status,
            body,
            content_type: "application/json".to_string(),
            headers: HashMap::new(),
            raw_body: Vec::new(),
        }
    }

    pub fn bytes(status: u16, content_type: impl Into<String>, body: Vec<u8>) -> Self {
        Self {
            status,
            body: JsonValue::Null,
            content_type: content_type.into(),
            headers: HashMap::new(),
            raw_body: body,
        }
    }

    pub fn event_stream(events: Vec<RealtimeEvent>) -> Self {
        let body = events.iter().flat_map(sse_event_bytes).collect::<Vec<u8>>();
        Self::bytes(200, "text/event-stream", body)
            .with_header("Cache-Control", "no-cache")
            .with_header("X-Accel-Buffering", "no")
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        self.headers
            .insert(normalize_http_header_name(&name), value.into());
        self
    }

    pub fn to_http_bytes(&self) -> Vec<u8> {
        let status_text = match self.status {
            200 => "OK",
            204 => "No Content",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "OK",
        };
        let body = if self.status == 204 {
            Vec::new()
        } else if self.content_type == "application/json" && self.raw_body.is_empty() {
            serde_json::to_vec(&self.body).unwrap_or_else(|_| b"{}".to_vec())
        } else {
            self.raw_body.clone()
        };
        let mut headers = self
            .headers
            .iter()
            .filter(|(name, _)| {
                !matches!(
                    name.as_str(),
                    "content-type" | "content-length" | "connection"
                )
            })
            .collect::<Vec<_>>();
        headers.sort_by(|(left, _), (right, _)| left.cmp(right));
        let mut extra_headers = String::new();
        for (name, value) in headers {
            extra_headers.push_str(name);
            extra_headers.push_str(": ");
            extra_headers.push_str(&sanitize_http_header_value(value));
            extra_headers.push_str("\r\n");
        }
        format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
            self.status,
            status_text,
            self.content_type,
            extra_headers,
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body)
        .collect()
    }
}

pub fn serve(addr: &str, db_path: impl AsRef<Path>) -> Result<(), ServerError> {
    let app = RustyBaseApp::new(Store::open(db_path)?);
    let listener = TcpListener::bind(addr)?;

    for stream in listener.incoming() {
        let app = app.clone();
        let stream = stream?;
        std::thread::spawn(move || {
            let _ = handle_stream(app, stream);
        });
    }

    Ok(())
}

pub(crate) fn handle_stream(app: RustyBaseApp, mut stream: TcpStream) -> Result<(), ServerError> {
    let request = parse_http_request(&mut stream)?;
    let (path, _) = split_path_query(&request.path);
    let segments = path_segments(&path);
    let segments = segments.iter().map(String::as_str).collect::<Vec<_>>();
    if request.method == "GET" && segments.as_slice() == ["api", "realtime"] {
        return handle_realtime_stream(app, stream);
    }

    let response = app.handle(request);
    stream.write_all(&response.to_http_bytes())?;
    Ok(())
}

pub(crate) fn handle_realtime_stream(
    app: RustyBaseApp,
    mut stream: TcpStream,
) -> Result<(), ServerError> {
    let connection = app.realtime_connect()?;
    stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nX-Accel-Buffering: no\r\nConnection: keep-alive\r\n\r\n",
    )?;

    loop {
        match connection.recv_timeout(REALTIME_IDLE_TIMEOUT) {
            Ok(event) => {
                stream.write_all(&sse_event_bytes(&event))?;
                stream.flush()?;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let event = RealtimeEvent {
                    event: "PB_DISCONNECT".to_string(),
                    data: json!({}),
                };
                stream.write_all(&sse_event_bytes(&event))?;
                stream.flush()?;
                break;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    app.realtime.remove_client(&connection.client_id);
    Ok(())
}

pub(crate) fn json_body_or_empty(body: &[u8]) -> Result<JsonValue, ServerError> {
    if body.is_empty() {
        Ok(JsonValue::Object(Map::new()))
    } else {
        serde_json::from_slice(body).map_err(ServerError::Json)
    }
}

pub(crate) fn batch_request_headers(
    value: Option<&JsonValue>,
) -> Result<HashMap<String, String>, ServerError> {
    let Some(value) = value else {
        return Ok(HashMap::new());
    };
    let Some(object) = value.as_object() else {
        return Err(validation_error(
            "Something went wrong while processing your request.",
            "headers",
            "validation_invalid_body",
            "Batch request headers must be an object.",
        ));
    };

    let mut headers = HashMap::new();
    for (name, value) in object {
        let Some(value) = value.as_str() else {
            return Err(validation_error(
                "Something went wrong while processing your request.",
                "headers",
                "validation_invalid_string",
                "Batch request header values must be strings.",
            ));
        };
        headers.insert(normalize_http_header_name(name), value.to_string());
    }

    Ok(headers)
}

pub(crate) fn ensure_supported_batch_request(method: &str, url: &str) -> Result<(), ServerError> {
    let (path, _) = split_path_query(url);
    let segments = path_segments(&path);
    let segments = segments.iter().map(String::as_str).collect::<Vec<_>>();
    let supported = matches!(
        (method, segments.as_slice()),
        ("POST", ["api", "collections", _, "records"])
            | ("PUT", ["api", "collections", _, "records"])
            | ("PATCH", ["api", "collections", _, "records", _])
            | ("DELETE", ["api", "collections", _, "records", _])
    );
    if supported {
        Ok(())
    } else {
        Err(ServerError::BadRequest(format!(
            "unsupported batch request '{method} {url}'"
        )))
    }
}

pub(crate) fn batch_request_failed(index: usize, response: &HttpResponse) -> ServerError {
    let response = batch_error_response_payload(response);
    let mut requests = Map::new();
    requests.insert(
        index.to_string(),
        json!({
            "code": "batch_request_failed",
            "message": "Batch request failed.",
            "response": response,
        }),
    );
    let mut data = Map::new();
    data.insert("requests".to_string(), JsonValue::Object(requests));

    ServerError::BadRequestData {
        message: "Batch transaction failed.".to_string(),
        data: JsonValue::Object(data),
    }
}

pub(crate) fn batch_error_response_payload(response: &HttpResponse) -> JsonValue {
    let message = response
        .body
        .get("message")
        .cloned()
        .unwrap_or_else(|| JsonValue::String("Batch request failed.".to_string()));
    let data = response
        .body
        .get("data")
        .cloned()
        .unwrap_or_else(|| json!({}));

    json!({
        "status": response.status,
        "message": message,
        "data": data,
    })
}

pub(crate) fn parse_http_request(stream: &mut TcpStream) -> Result<HttpRequest, ServerError> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| ServerError::BadRequest("missing HTTP method".to_string()))?;
    let path = request_parts
        .next()
        .ok_or_else(|| ServerError::BadRequest("missing HTTP path".to_string()))?;

    let mut headers = HashMap::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }

        if let Some((name, value)) = line.split_once(':') {
            let name = normalize_http_header_name(name);
            let value = value.trim().to_string();
            if name == "content-length" {
                content_length = value.parse().map_err(|_| {
                    ServerError::BadRequest("invalid Content-Length header".to_string())
                })?;
            }
            headers.insert(name, value);
        }
    }

    let mut body = vec![0; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    Ok(HttpRequest {
        method: method.to_string(),
        path: path.to_string(),
        headers,
        body,
    })
}

pub(crate) fn split_path_query(path: &str) -> (String, HashMap<String, String>) {
    let Some((path, query)) = path.split_once('?') else {
        return (path.to_string(), HashMap::new());
    };

    (path.to_string(), parse_query(query))
}

pub(crate) fn path_segments(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .map(percent_decode)
        .collect()
}

pub(crate) fn parse_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            (percent_decode(key), percent_decode(value))
        })
        .collect()
}

pub(crate) fn percent_encode_query_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
                out.push(char::from(b"0123456789ABCDEF"[(byte & 0x0f) as usize]));
            }
        }
    }
    out
}

pub(crate) fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = &value[index + 1..index + 3];
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    index += 3;
                } else {
                    out.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn normalize_http_header_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

pub(crate) fn sanitize_http_header_value(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch == '\r' || ch == '\n' { ' ' } else { ch })
        .collect()
}

pub(crate) fn content_disposition_attachment(filename: &str) -> String {
    format!(
        "attachment; filename=\"{}\"",
        filename
            .chars()
            .map(|ch| {
                if ch == '"' || ch == '\\' || ch == '\r' || ch == '\n' {
                    '_'
                } else {
                    ch
                }
            })
            .collect::<String>()
    )
}

pub(crate) fn error_response(err: ServerError) -> HttpResponse {
    let status = match &err {
        ServerError::BadRequest(_)
        | ServerError::BadRequestData { .. }
        | ServerError::Json(_)
        | ServerError::Filter(_) => 400,
        ServerError::Forbidden(_) => 403,
        ServerError::NotFound(_) => 404,
        ServerError::Storage(_) | ServerError::Io(_) => 500,
    };
    let data = match &err {
        ServerError::BadRequestData { data, .. } => data.clone(),
        _ => json!({}),
    };

    HttpResponse::json(
        status,
        json!({
            "code": status,
            "message": err.to_string(),
            "data": data,
        }),
    )
}
