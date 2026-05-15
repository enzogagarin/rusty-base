use super::*;

impl RustyBaseApp {
    pub(crate) fn require_superuser_admin(&self, request: &HttpRequest) -> Result<(), ServerError> {
        if !self.store.superuser_auth_is_required()? {
            return Ok(());
        }

        self.require_superuser_token(request)
    }

    pub(crate) fn require_superuser_token(&self, request: &HttpRequest) -> Result<(), ServerError> {
        let token = bearer_token(request)
            .ok_or_else(|| ServerError::Forbidden("missing superuser auth token".to_string()))?;
        if self.store.is_superuser_token(token)? {
            Ok(())
        } else {
            Err(ServerError::Forbidden(
                "superuser auth token is required".to_string(),
            ))
        }
    }

    pub(crate) fn require_superuser_record_access(
        &self,
        collection: &str,
        request: &HttpRequest,
    ) -> Result<(), ServerError> {
        if collection == SUPERUSERS_COLLECTION {
            self.require_superuser_admin(request)?;
        }

        Ok(())
    }
}
