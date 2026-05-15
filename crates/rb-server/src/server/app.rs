use super::*;
use super::{
    admin::*, auth::*, collections::*, files::*, http::*, realtime::*, records::*, settings::*,
    storage::*, validation::*,
};

mod access;
mod batch;
mod context;
mod realtime_events;
mod routes;

#[derive(Clone)]
pub struct RustyBaseApp {
    pub(crate) store: Arc<Store>,
    pub(crate) realtime: Arc<RealtimeBroker>,
}

impl RustyBaseApp {
    pub fn new(store: Store) -> Self {
        Self {
            store: Arc::new(store),
            realtime: Arc::new(RealtimeBroker::default()),
        }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn realtime_connect(&self) -> Result<RealtimeConnection, ServerError> {
        self.realtime.connect()
    }

    pub fn handle(&self, request: HttpRequest) -> HttpResponse {
        match self.handle_result(request) {
            Ok(response) => response,
            Err(err) => error_response(err),
        }
    }
}
