use super::*;

impl RustyBaseApp {
    pub(crate) fn handle_batch(&self, request: HttpRequest) -> Result<HttpResponse, ServerError> {
        let settings = self.store.get_settings()?;
        if !settings.batch.enabled {
            return Err(ServerError::BadRequest(
                "Batch API is disabled.".to_string(),
            ));
        }
        if settings.batch.max_body_size > 0
            && request.body.len() as u64 > settings.batch.max_body_size
        {
            return Err(validation_error(
                "Something went wrong while processing your request.",
                "body",
                "validation_max_size",
                format!(
                    "Batch request body cannot exceed {} bytes.",
                    settings.batch.max_body_size
                ),
            ));
        }
        let max_requests = usize::try_from(settings.batch.max_requests).unwrap_or(usize::MAX);
        let batch =
            BatchRequestBody::from_json(serde_json::from_slice(&request.body)?, max_requests)?;
        self.store.begin_batch_transaction()?;

        let mut responses = Vec::with_capacity(batch.requests.len());
        for (index, item) in batch.requests.into_iter().enumerate() {
            let child = match self.batch_http_request(&request, item) {
                Ok(request) => request,
                Err(err) => {
                    let response = error_response(err);
                    let _ = self.store.rollback_batch_transaction();
                    return Err(batch_request_failed(index, &response));
                }
            };
            let response = self.handle(child);
            if response.status >= 400 {
                let _ = self.store.rollback_batch_transaction();
                return Err(batch_request_failed(index, &response));
            }
            responses.push(json!({
                "status": response.status,
                "body": response.body,
            }));
        }

        self.store.commit_batch_transaction()?;
        Ok(HttpResponse::json(200, JsonValue::Array(responses)))
    }

    pub(crate) fn batch_http_request(
        &self,
        parent: &HttpRequest,
        item: BatchRequestInput,
    ) -> Result<HttpRequest, ServerError> {
        if item
            .headers
            .keys()
            .any(|name| name == "authorization" || name == "x-rb-auth-id")
        {
            return Err(ServerError::BadRequest(
                "custom batch auth headers are not supported".to_string(),
            ));
        }

        let mut method = item.method;
        let original_path = item.url;
        let mut path = original_path.clone();
        let body = item.body;
        ensure_supported_batch_request(&method, &path)?;

        if method == "PUT" {
            let (path_only, query_suffix) = match path.split_once('?') {
                Some((path_only, query)) => (path_only.to_string(), format!("?{query}")),
                None => (path.clone(), String::new()),
            };
            let segments = path_segments(&path_only);
            let collection = segments
                .get(2)
                .map(String::as_str)
                .ok_or_else(|| ServerError::BadRequest("invalid batch request url".to_string()))?;
            let id = body
                .as_object()
                .and_then(|object| object.get("id"))
                .and_then(JsonValue::as_str)
                .filter(|id| !id.trim().is_empty())
                .ok_or_else(|| {
                    validation_error(
                        "Something went wrong while processing your request.",
                        "id",
                        "validation_required",
                        "Upsert batch requests require a body id.",
                    )
                })?;
            validate_record_id(id)?;

            method = if self.store.read_record(collection, id).is_ok() {
                "PATCH".to_string()
            } else {
                "POST".to_string()
            };
            path = if method == "PATCH" {
                format!("/api/collections/{collection}/records/{id}{query_suffix}")
            } else {
                original_path
            };
        }

        let mut headers = item.headers;
        if let Some(value) = parent.headers.get("authorization") {
            headers.insert("authorization".to_string(), value.clone());
        }
        if let Some(value) = parent.headers.get("x-rb-auth-id") {
            headers.insert("x-rb-auth-id".to_string(), value.clone());
        }

        let body = if body.is_null() {
            Vec::new()
        } else {
            headers
                .entry("content-type".to_string())
                .or_insert_with(|| "application/json".to_string());
            serde_json::to_vec(&body)?
        };

        Ok(HttpRequest {
            method,
            path,
            headers,
            body,
        })
    }
}
