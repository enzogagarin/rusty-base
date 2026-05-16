use super::*;

impl RustyBaseApp {
    pub(crate) fn handle_result(&self, request: HttpRequest) -> Result<HttpResponse, ServerError> {
        let (path, query) = split_path_query(&request.path);
        let segments = path_segments(&path);
        let segments = segments.iter().map(String::as_str).collect::<Vec<_>>();

        match (request.method.as_str(), segments.as_slice()) {
            ("GET", ["_", "admin", assets @ ..]) if !assets.is_empty() => {
                let asset = assets.join("/");
                admin_asset_response(&asset).ok_or_else(|| {
                    ServerError::NotFound(format!("admin asset '{asset}' not found"))
                })
            }
            ("GET", ["admin", ..]) | ("GET", ["_", ..]) => Ok(admin_index_response()),
            ("GET", ["api", "health"]) => Ok(HttpResponse::json(
                200,
                json!({"code": 200, "message": "API is healthy."}),
            )),
            ("GET", ["api", "realtime"]) => {
                let connection = self.realtime_connect()?;
                Ok(HttpResponse::event_stream(vec![RealtimeEvent {
                    event: "PB_CONNECT".to_string(),
                    data: json!({ "clientId": connection.client_id }),
                }]))
            }
            ("POST", ["api", "realtime"]) => {
                let subscribe =
                    RealtimeSubscribeRequest::from_json(serde_json::from_slice(&request.body)?)?;
                let subscriptions = realtime_subscriptions(&subscribe.subscriptions)?;
                for subscription in &subscriptions {
                    self.store.get_collection(&subscription.collection)?;
                }
                let context = self.request_context(&request, &query)?;
                self.realtime
                    .set_subscriptions(&subscribe.client_id, subscriptions, context)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("POST", ["api", "batch"]) => self.handle_batch(request),
            ("GET", ["api", "settings"]) => {
                self.require_superuser_admin(&request)?;
                let mut payload = settings_response_payload(self.store.get_settings()?)?;
                let fields = field_options_from_query(&query)?;
                project_json_response(&mut payload, &fields)?;
                Ok(HttpResponse::json(200, payload))
            }
            ("PATCH", ["api", "settings"]) => {
                self.require_superuser_admin(&request)?;
                let body = json_body_or_empty(&request.body)?;
                let mut payload = settings_response_payload(self.store.update_settings(body)?)?;
                let fields = field_options_from_query(&query)?;
                project_json_response(&mut payload, &fields)?;
                Ok(HttpResponse::json(200, payload))
            }
            ("GET", ["api", "dev", "mail", "outbox"]) => {
                self.require_superuser_admin(&request)?;
                let mut payload = self.store.list_mail_outbox()?;
                let fields = field_options_from_query(&query)?;
                project_json_response(&mut payload, &fields)?;
                Ok(HttpResponse::json(200, payload))
            }
            ("DELETE", ["api", "dev", "mail", "outbox"]) => {
                self.require_superuser_admin(&request)?;
                self.store.clear_mail_outbox()?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("POST", ["api", "files", "token"]) => {
                let auth_token = bearer_token(&request)
                    .ok_or_else(|| ServerError::Forbidden("missing auth token".to_string()))?;
                let token = self.store.create_file_token(auth_token)?;
                Ok(HttpResponse::json(200, json!({ "token": token })))
            }
            ("GET", ["api", "files", collection, record_id, filename]) => {
                let collection_config = self.store.get_collection(collection)?;
                let record = self.store.read_record(collection, record_id)?;
                let Some(referenced_file) = referenced_file(&collection_config, &record, filename)?
                else {
                    return Err(ServerError::NotFound(format!(
                        "file '{filename}' not found"
                    )));
                };
                if referenced_file.protected {
                    let context = self.file_request_context(&request, &query)?;
                    let record = self.store.get_record(collection, record_id, context)?;
                    if !record_references_file(&collection_config, &record, filename)? {
                        return Err(ServerError::NotFound(format!(
                            "file '{filename}' not found"
                        )));
                    }
                }
                let mut file = self.store.get_file(collection, record_id, filename)?;
                if let Some(thumb) = query.get("thumb").filter(|thumb| !thumb.trim().is_empty()) {
                    file = thumbnail_file(file, thumb, &referenced_file.thumbs);
                }
                let mut response = HttpResponse::bytes(200, file.content_type, file.data);
                if truthy_query_value(&query, "download") {
                    response = response.with_header(
                        "Content-Disposition",
                        content_disposition_attachment(filename),
                    );
                }
                Ok(response)
            }
            ("GET", ["api", "collections"]) => {
                self.require_superuser_admin(&request)?;
                let list = self
                    .store
                    .list_collection_page(collection_list_options_from_query(&query)?)?;
                Ok(HttpResponse::json(200, list))
            }
            ("POST", ["api", "collections"]) => {
                self.require_superuser_admin(&request)?;
                let collection: CollectionConfig = serde_json::from_slice(&request.body)?;
                let collection = self.store.create_collection(collection)?;
                let fields = field_options_from_query(&query)?;
                let payload = self
                    .store
                    .get_collection_response(&collection.name, &fields)?;
                Ok(HttpResponse::json(200, payload))
            }
            ("PUT", ["api", "collections", "import"]) => {
                self.require_superuser_admin(&request)?;
                let request =
                    CollectionImportRequest::from_json(serde_json::from_slice(&request.body)?)?;
                self.store.import_collections(request)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("GET", ["api", "collections", "meta", "scaffolds"]) => {
                self.require_superuser_admin(&request)?;
                Ok(HttpResponse::json(200, collection_scaffolds()))
            }
            ("GET", ["api", "collections", "meta", "export"]) => {
                self.require_superuser_admin(&request)?;
                let collections = self.store.list_collections()?;
                Ok(HttpResponse::json(
                    200,
                    collection_export_payload(collections),
                ))
            }
            ("GET", ["api", "collections", collection]) => {
                self.require_superuser_admin(&request)?;
                let fields = field_options_from_query(&query)?;
                let payload = self.store.get_collection_response(collection, &fields)?;
                Ok(HttpResponse::json(200, payload))
            }
            ("PATCH", ["api", "collections", collection]) => {
                self.require_superuser_admin(&request)?;
                let patch: CollectionPatch = serde_json::from_slice(&request.body)?;
                let collection = self.store.update_collection(collection, patch)?;
                let fields = field_options_from_query(&query)?;
                let payload = self
                    .store
                    .get_collection_response(&collection.name, &fields)?;
                Ok(HttpResponse::json(200, payload))
            }
            ("DELETE", ["api", "collections", collection]) => {
                self.require_superuser_admin(&request)?;
                self.store.delete_collection(collection)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("DELETE", ["api", "collections", collection, "truncate"]) => {
                self.require_superuser_admin(&request)?;
                self.store.truncate_collection(collection)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("GET", ["api", "collections", collection, "auth-methods"]) => {
                let collection = self.store.get_collection(collection)?;
                let mut payload = auth_methods_payload(&collection)?;
                let fields = field_options_from_query(&query)?;
                project_json_response(&mut payload, &fields)?;
                Ok(HttpResponse::json(200, payload))
            }
            ("POST", ["api", "collections", collection, "request-verification"]) => {
                let request = AuthEmailRequest::from_json(serde_json::from_slice(&request.body)?)?;
                self.store
                    .request_verification(collection, &request.email)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("POST", ["api", "collections", collection, "confirm-verification"]) => {
                let request = AuthTokenRequest::from_json(serde_json::from_slice(&request.body)?)?;
                self.store
                    .confirm_verification(collection, &request.token)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("POST", ["api", "collections", collection, "request-password-reset"]) => {
                let request = AuthEmailRequest::from_json(serde_json::from_slice(&request.body)?)?;
                self.store
                    .request_password_reset(collection, &request.email)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("POST", ["api", "collections", collection, "confirm-password-reset"]) => {
                let request =
                    ConfirmPasswordResetRequest::from_json(serde_json::from_slice(&request.body)?)?;
                self.store.confirm_password_reset(
                    collection,
                    &request.token,
                    &request.password,
                    &request.password_confirm,
                )?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("POST", ["api", "collections", collection, "request-email-change"]) => {
                let token = bearer_token(&request)
                    .ok_or_else(|| ServerError::Forbidden("missing auth token".to_string()))?;
                let request =
                    AuthNewEmailRequest::from_json(serde_json::from_slice(&request.body)?)?;
                self.store
                    .request_email_change(collection, token, &request.new_email)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("POST", ["api", "collections", collection, "confirm-email-change"]) => {
                let request =
                    ConfirmEmailChangeRequest::from_json(serde_json::from_slice(&request.body)?)?;
                self.store
                    .confirm_email_change(collection, &request.token, &request.password)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("POST", ["api", "collections", collection, "auth-with-password"]) => {
                let auth =
                    AuthWithPasswordRequest::from_json(serde_json::from_slice(&request.body)?)?;
                let response =
                    self.store
                        .auth_with_password(collection, &auth.identity, &auth.password)?;
                let expands = expand_options_from_query(&query)?;
                let fields = field_options_from_query(&query)?;
                let payload = auth_response_payload(
                    &self.store,
                    collection,
                    response,
                    &expands,
                    &fields,
                    request_context(&request, &query),
                )?;
                Ok(HttpResponse::json(200, payload))
            }
            ("POST", ["api", "collections", collection, "request-otp"]) => {
                let request = AuthEmailRequest::from_json(serde_json::from_slice(&request.body)?)?;
                let otp_id = self.store.request_otp(collection, &request.email)?;
                Ok(HttpResponse::json(200, json!({ "otpId": otp_id })))
            }
            ("POST", ["api", "collections", collection, "auth-with-otp"]) => {
                let auth = AuthWithOtpRequest::from_json(serde_json::from_slice(&request.body)?)?;
                let response =
                    self.store
                        .auth_with_otp(collection, &auth.otp_id, &auth.password)?;
                let expands = expand_options_from_query(&query)?;
                let fields = field_options_from_query(&query)?;
                let payload = auth_response_payload(
                    &self.store,
                    collection,
                    response,
                    &expands,
                    &fields,
                    request_context(&request, &query),
                )?;
                Ok(HttpResponse::json(200, payload))
            }
            ("POST", ["api", "collections", collection, "auth-with-oauth2"]) => {
                let auth =
                    AuthWithOAuth2Request::from_json(serde_json::from_slice(&request.body)?)?;
                let profile = if let Some(profile) = oauth2_profile_from_code(&auth.code)? {
                    profile
                } else {
                    let collection_config = self.store.auth_collection(collection)?;
                    let provider_config =
                        oauth2_provider_configured(&collection_config, &auth.provider)?;
                    exchange_oauth2_code(&collection_config, provider_config, &auth)?
                };
                let (response, meta) = self.store.auth_with_oauth2_profile(
                    collection,
                    &auth.provider,
                    profile,
                    &auth.create_data,
                )?;
                let expands = expand_options_from_query(&query)?;
                let fields = field_options_from_query(&query)?;
                let payload = oauth2_auth_response_payload(
                    &self.store,
                    collection,
                    response,
                    meta,
                    &expands,
                    &fields,
                    request_context(&request, &query),
                )?;
                Ok(HttpResponse::json(200, payload))
            }
            ("POST", ["api", "collections", collection, "auth-refresh"]) => {
                let token = bearer_token(&request)
                    .ok_or_else(|| ServerError::Forbidden("missing auth token".to_string()))?;
                let response = self.store.auth_refresh(collection, token)?;
                let expands = expand_options_from_query(&query)?;
                let fields = field_options_from_query(&query)?;
                let payload = auth_response_payload(
                    &self.store,
                    collection,
                    response,
                    &expands,
                    &fields,
                    request_context(&request, &query),
                )?;
                Ok(HttpResponse::json(200, payload))
            }
            ("POST", ["api", "collections", collection, "impersonate", id]) => {
                self.require_superuser_token(&request)?;
                let body = json_body_or_empty(&request.body)?;
                let impersonate = ImpersonateRequest::from_json(body)?;
                let response =
                    self.store
                        .impersonate_auth_record(collection, id, impersonate.duration)?;
                let expands = expand_options_from_query(&query)?;
                let fields = field_options_from_query(&query)?;
                let payload = auth_response_payload(
                    &self.store,
                    collection,
                    response,
                    &expands,
                    &fields,
                    request_context(&request, &query),
                )?;
                Ok(HttpResponse::json(200, payload))
            }
            ("POST", ["api", "collections", collection, "auth-logout"]) => {
                let token = bearer_token(&request)
                    .ok_or_else(|| ServerError::Forbidden("missing auth token".to_string()))?;
                self.store.revoke_auth_token(collection, token)?;
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            ("GET", ["api", "collections", collection, "records"]) => {
                self.require_superuser_record_access(collection, &request)?;
                let options =
                    list_options_from_query(&query, self.request_context(&request, &query)?)?;
                let list = self.store.list_records(collection, options)?;
                Ok(HttpResponse::json(200, json!(list)))
            }
            ("POST", ["api", "collections", collection, "records"]) => {
                self.require_superuser_record_access(collection, &request)?;
                let collection_config = self.store.get_collection(collection)?;
                let (data, uploads) = record_payload_from_request(&request, &collection_config)?;
                let context = self.request_context(&request, &query)?;
                let mut record = self.store.create_record_with_uploads(
                    collection,
                    data,
                    uploads,
                    context.clone(),
                )?;
                let realtime_record = record.clone();
                let expands = expand_options_from_query(&query)?;
                self.store
                    .expand_record_response(collection, &mut record, &expands, &context)?;
                let fields = field_options_from_query(&query)?;
                project_record_response(&mut record, &fields)?;
                self.publish_realtime_record_event(collection, "create", &realtime_record);
                Ok(HttpResponse::json(200, record))
            }
            ("GET", ["api", "collections", collection, "records", id]) => {
                self.require_superuser_record_access(collection, &request)?;
                let context = self.request_context(&request, &query)?;
                let mut record = self.store.get_record(collection, id, context.clone())?;
                let expands = expand_options_from_query(&query)?;
                self.store
                    .expand_record_response(collection, &mut record, &expands, &context)?;
                let fields = field_options_from_query(&query)?;
                project_record_response(&mut record, &fields)?;
                Ok(HttpResponse::json(200, record))
            }
            ("PATCH", ["api", "collections", collection, "records", id]) => {
                self.require_superuser_record_access(collection, &request)?;
                let collection_config = self.store.get_collection(collection)?;
                let (patch, uploads) = record_payload_from_request(&request, &collection_config)?;
                let context = self.request_context(&request, &query)?;
                let mut record = self.store.update_record_with_uploads(
                    collection,
                    id,
                    patch,
                    uploads,
                    context.clone(),
                )?;
                let realtime_record = record.clone();
                let expands = expand_options_from_query(&query)?;
                self.store
                    .expand_record_response(collection, &mut record, &expands, &context)?;
                let fields = field_options_from_query(&query)?;
                project_record_response(&mut record, &fields)?;
                self.publish_realtime_record_event(collection, "update", &realtime_record);
                Ok(HttpResponse::json(200, record))
            }
            ("DELETE", ["api", "collections", collection, "records", id]) => {
                self.require_superuser_record_access(collection, &request)?;
                let realtime_record = self.store.read_record(collection, id).ok();
                let realtime_deliveries = realtime_record
                    .as_ref()
                    .map(|record| self.realtime_deliveries(collection, "delete", record))
                    .unwrap_or_default();
                self.store.delete_record_with_context(
                    collection,
                    id,
                    self.request_context(&request, &query)?,
                )?;
                self.send_realtime_deliveries(realtime_deliveries);
                Ok(HttpResponse::json(204, JsonValue::Null))
            }
            _ => Err(ServerError::NotFound(format!(
                "route '{} {}' not found",
                request.method, request.path
            ))),
        }
    }
}
