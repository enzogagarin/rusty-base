use super::*;

impl RustyBaseApp {
    pub(crate) fn publish_realtime_record_event(
        &self,
        collection: &str,
        action: &str,
        record: &JsonValue,
    ) {
        let deliveries = self.realtime_deliveries(collection, action, record);
        self.send_realtime_deliveries(deliveries);
    }

    pub(crate) fn realtime_deliveries(
        &self,
        collection_name: &str,
        action: &str,
        record: &JsonValue,
    ) -> Vec<RealtimeDelivery> {
        let Some(record_id) = record.get("id").and_then(JsonValue::as_str) else {
            return Vec::new();
        };
        let Ok(collection) = self.store.get_collection(collection_name) else {
            return Vec::new();
        };

        let mut deliveries = Vec::new();
        for client in self.realtime.snapshots() {
            for subscription in client
                .subscriptions
                .iter()
                .filter(|subscription| subscription.collection == collection_name)
                .filter(|subscription| {
                    subscription
                        .record_id
                        .as_deref()
                        .is_none_or(|subscribed_id| subscribed_id == record_id)
                })
            {
                if !self.realtime_subscription_allows(
                    &collection,
                    subscription,
                    record_id,
                    &client.context,
                ) {
                    continue;
                }

                let mut record = record.clone();
                if sanitize_record_response(&collection, &mut record, &client.context).is_err() {
                    continue;
                }
                let payload = json!({
                    "action": action,
                    "record": record,
                });
                deliveries.push(RealtimeDelivery {
                    client_id: client.client_id.clone(),
                    sender: client.sender.clone(),
                    event: RealtimeEvent {
                        event: subscription.topic(),
                        data: payload.clone(),
                    },
                });
            }
        }

        deliveries
    }

    pub(crate) fn realtime_subscription_allows(
        &self,
        collection: &CollectionConfig,
        subscription: &RealtimeSubscription,
        record_id: &str,
        context: &FilterContext,
    ) -> bool {
        let rule = if subscription.record_id.is_some() {
            collection.view_rule.as_deref()
        } else {
            collection.list_rule.as_deref()
        };

        self.store
            .existing_record_rule_allows(
                &collection.name,
                collection,
                rule,
                record_id,
                context.clone(),
            )
            .unwrap_or(false)
    }

    pub(crate) fn send_realtime_deliveries(&self, deliveries: Vec<RealtimeDelivery>) {
        for delivery in deliveries {
            if delivery.sender.send(delivery.event).is_err() {
                self.realtime.remove_client(&delivery.client_id);
            }
        }
    }
}
