use super::*;
use super::{auth::*, storage::*, validation::*};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealtimeEvent {
    pub event: String,
    pub data: JsonValue,
}

pub struct RealtimeConnection {
    pub client_id: String,
    pub(crate) receiver: mpsc::Receiver<RealtimeEvent>,
}

impl RealtimeConnection {
    pub fn recv_timeout(&self, timeout: Duration) -> Result<RealtimeEvent, mpsc::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RealtimeSubscription {
    pub(crate) collection: String,
    pub(crate) record_id: Option<String>,
}

impl RealtimeSubscription {
    pub(crate) fn topic(&self) -> String {
        match &self.record_id {
            Some(record_id) => format!("{}/{record_id}", self.collection),
            None => format!("{}/*", self.collection),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RealtimeClient {
    pub(crate) sender: mpsc::Sender<RealtimeEvent>,
    pub(crate) subscriptions: Vec<RealtimeSubscription>,
    pub(crate) context: FilterContext,
}

#[derive(Debug, Clone)]
pub(crate) struct RealtimeClientSnapshot {
    pub(crate) client_id: String,
    pub(crate) sender: mpsc::Sender<RealtimeEvent>,
    pub(crate) subscriptions: Vec<RealtimeSubscription>,
    pub(crate) context: FilterContext,
}

#[derive(Debug, Clone)]
pub(crate) struct RealtimeDelivery {
    pub(crate) client_id: String,
    pub(crate) sender: mpsc::Sender<RealtimeEvent>,
    pub(crate) event: RealtimeEvent,
}

#[derive(Debug, Default)]
pub(crate) struct RealtimeBroker {
    pub(crate) clients: Mutex<HashMap<String, RealtimeClient>>,
}

impl RealtimeBroker {
    pub(crate) fn connect(&self) -> Result<RealtimeConnection, ServerError> {
        let client_id = generate_id();
        let (sender, receiver) = mpsc::channel();
        let connection = RealtimeConnection {
            client_id: client_id.clone(),
            receiver,
        };
        let client = RealtimeClient {
            sender: sender.clone(),
            subscriptions: Vec::new(),
            context: FilterContext::default(),
        };

        self.clients
            .lock()
            .map_err(|_| ServerError::Storage(rusqlite::Error::InvalidQuery))?
            .insert(client_id.clone(), client);
        let _ = sender.send(RealtimeEvent {
            event: "PB_CONNECT".to_string(),
            data: json!({ "clientId": client_id }),
        });

        Ok(connection)
    }

    pub(crate) fn set_subscriptions(
        &self,
        client_id: &str,
        subscriptions: Vec<RealtimeSubscription>,
        context: FilterContext,
    ) -> Result<(), ServerError> {
        let mut clients = self
            .clients
            .lock()
            .map_err(|_| ServerError::Storage(rusqlite::Error::InvalidQuery))?;
        let client = clients
            .get_mut(client_id)
            .ok_or_else(|| ServerError::NotFound("Missing or invalid client id.".to_string()))?;

        client.subscriptions = subscriptions;
        client.context = context;
        Ok(())
    }

    pub(crate) fn snapshots(&self) -> Vec<RealtimeClientSnapshot> {
        let Ok(clients) = self.clients.lock() else {
            return Vec::new();
        };

        clients
            .iter()
            .map(|(client_id, client)| RealtimeClientSnapshot {
                client_id: client_id.clone(),
                sender: client.sender.clone(),
                subscriptions: client.subscriptions.clone(),
                context: client.context.clone(),
            })
            .collect()
    }

    pub(crate) fn remove_client(&self, client_id: &str) {
        if let Ok(mut clients) = self.clients.lock() {
            clients.remove(client_id);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RealtimeSubscribeRequest {
    pub(crate) client_id: String,
    #[serde(default)]
    pub(crate) subscriptions: Vec<String>,
}

impl RealtimeSubscribeRequest {
    pub(crate) fn from_json(value: JsonValue) -> Result<Self, ServerError> {
        let object = value.as_object().ok_or_else(|| {
            validation_error(
                "Something went wrong while processing your request.",
                "body",
                "validation_invalid_body",
                "Request body must be a JSON object.",
            )
        })?;

        let client_id = required_form_string(
            object,
            "clientId",
            "Something went wrong while processing your request.",
        )?;
        let subscriptions = object
            .get("subscriptions")
            .and_then(JsonValue::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(JsonValue::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            client_id,
            subscriptions,
        })
    }
}

pub(crate) fn realtime_subscriptions(
    values: &[String],
) -> Result<Vec<RealtimeSubscription>, ServerError> {
    let mut subscriptions = Vec::new();
    for value in values {
        let topic = value
            .split_once('?')
            .map_or(value.as_str(), |(topic, _)| topic);
        let topic = topic.trim().trim_matches('/');
        if topic.is_empty() {
            continue;
        }
        let Some((collection, target)) = topic.split_once('/') else {
            return Err(ServerError::BadRequest(format!(
                "invalid realtime subscription '{value}'"
            )));
        };
        validate_collection_name(collection)?;
        let record_id = if target == "*" {
            None
        } else {
            validate_record_id(target)?;
            Some(target.to_string())
        };
        subscriptions.push(RealtimeSubscription {
            collection: collection.to_string(),
            record_id,
        });
    }
    dedupe_realtime_subscriptions(&mut subscriptions);

    Ok(subscriptions)
}

pub(crate) fn dedupe_realtime_subscriptions(subscriptions: &mut Vec<RealtimeSubscription>) {
    let mut seen = HashSet::new();
    subscriptions.retain(|subscription| seen.insert(subscription.topic()));
}

pub(crate) fn sse_event_bytes(event: &RealtimeEvent) -> Vec<u8> {
    let data = serde_json::to_string(&event.data).unwrap_or_else(|_| "{}".to_string());
    format!(
        "event: {}\ndata: {data}\n\n",
        sanitize_sse_event(&event.event)
    )
    .into_bytes()
}

pub(crate) fn sanitize_sse_event(event: &str) -> String {
    event
        .chars()
        .filter(|ch| *ch != '\r' && *ch != '\n')
        .collect()
}
