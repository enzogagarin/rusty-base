use super::*;

impl RustyBaseApp {
    pub(crate) fn request_context(
        &self,
        request: &HttpRequest,
        query: &HashMap<String, String>,
    ) -> Result<FilterContext, ServerError> {
        let context = request_context(request, query);
        let Some(token) = bearer_token(request) else {
            return Ok(context);
        };

        match self.store.context_for_token(token, context.clone()) {
            Ok(context) => Ok(context),
            Err(ServerError::Forbidden(_)) => Ok(context),
            Err(err) => Err(err),
        }
    }

    pub(crate) fn file_request_context(
        &self,
        request: &HttpRequest,
        query: &HashMap<String, String>,
    ) -> Result<FilterContext, ServerError> {
        let context = request_context(request, query);
        if let Some(token) = query.get("token").filter(|token| !token.trim().is_empty()) {
            return self.store.context_for_file_token(token, context);
        }

        self.request_context(request, query)
    }
}
