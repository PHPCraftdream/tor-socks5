use std::{
    cell::RefCell,
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, RwLock},
};

use tracing_subscriber::{layer::Layer, layer::SubscriberExt, Registry};

pub(super) type DynamicLogLayer = Box<dyn Layer<Registry> + Send + Sync + 'static>;

pub(super) struct LogConfig {
    pub(super) filter: Arc<tracing_subscriber::EnvFilter>,
    pub(super) sink: Arc<DynamicLogLayer>,
}

pub(super) struct ManagedLayer {
    pub(super) inner: Arc<RwLock<LogConfig>>,
    spans: Mutex<HashMap<tracing::span::Id, SpanState>>,
    callsites: Arc<Mutex<Vec<&'static tracing::Metadata<'static>>>>,
}

#[derive(Clone)]
struct SpanState {
    metadata: &'static tracing::Metadata<'static>,
    values: Vec<Option<StoredValue>>,
}

#[derive(Clone)]
enum StoredValue {
    Bool(bool),
    F64(f64),
    I64(i64),
    U64(u64),
    String(String),
    Debug(String),
}

struct RawDebug(String);

impl fmt::Debug for RawDebug {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl StoredValue {
    fn as_value(&self) -> Box<dyn tracing::field::Value> {
        match self {
            Self::Bool(value) => Box::new(*value),
            Self::F64(value) => Box::new(*value),
            Self::I64(value) => Box::new(*value),
            Self::U64(value) => Box::new(*value),
            Self::String(value) => Box::new(value.clone()),
            Self::Debug(value) => Box::new(tracing::field::debug(RawDebug(value.clone()))),
        }
    }
}

struct SpanValueVisitor<'a> {
    metadata: &'static tracing::Metadata<'static>,
    values: &'a mut [Option<StoredValue>],
}

impl SpanValueVisitor<'_> {
    fn slot(&mut self, field: &tracing::field::Field) -> Option<&mut Option<StoredValue>> {
        self.metadata
            .fields()
            .field(field.name())
            .and_then(|field| self.values.get_mut(field.index()))
    }
}

impl tracing::field::Visit for SpanValueVisitor<'_> {
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        if let Some(slot) = self.slot(field) {
            *slot = Some(StoredValue::Bool(value));
        }
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        if let Some(slot) = self.slot(field) {
            *slot = Some(StoredValue::F64(value));
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        if let Some(slot) = self.slot(field) {
            *slot = Some(StoredValue::I64(value));
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if let Some(slot) = self.slot(field) {
            *slot = Some(StoredValue::U64(value));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if let Some(slot) = self.slot(field) {
            *slot = Some(StoredValue::String(value.to_owned()));
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if let Some(slot) = self.slot(field) {
            *slot = Some(StoredValue::Debug(format!("{value:?}")));
        }
    }
}

thread_local! {
    static ACTIVE_SPANS: RefCell<Vec<tracing::span::Id>> = const { RefCell::new(Vec::new()) };
    static BOUND_FILTER: RefCell<Option<Arc<tracing_subscriber::EnvFilter>>> = const { RefCell::new(None) };
}

type LayeredSubscriber = tracing_subscriber::layer::Layered<ManagedLayer, Registry>;

pub(super) struct OwnedDispatcher {
    pub(super) inner: Arc<RwLock<LogConfig>>,
    pub(super) callsites: Arc<Mutex<Vec<&'static tracing::Metadata<'static>>>>,
    subscriber: LayeredSubscriber,
}

impl Layer<Registry> for ManagedLayer {
    fn on_layer(&mut self, subscriber: &mut Registry) {
        if let Ok(mut layer) = self.inner.write() {
            if let Some(sink) = Arc::get_mut(&mut layer.sink) {
                sink.on_layer(subscriber);
            }
        }
    }

    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        let mut callsites = self
            .callsites
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !callsites.iter().any(|known| std::ptr::eq(*known, metadata)) {
            callsites.push(metadata);
        }
        let filter = self.current_filter();
        let _ = <tracing_subscriber::EnvFilter as Layer<Registry>>::register_callsite(
            &*filter, metadata,
        );
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(
        &self,
        metadata: &tracing::Metadata<'_>,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) -> bool {
        let filter = self.new_span_filter(&ctx);
        let enabled = filter.enabled(metadata, ctx.clone());
        enabled
            && self
                .inner
                .read()
                .map(|layer| Arc::clone(&layer.sink))
                .map(|sink| sink.enabled(metadata, ctx))
                .unwrap_or(false)
    }

    fn event_enabled(
        &self,
        event: &tracing::Event<'_>,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) -> bool {
        self.inner
            .read()
            .map(|layer| Arc::clone(&layer.sink))
            .map(|sink| sink.event_enabled(event, ctx))
            .unwrap_or(false)
    }

    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) {
        if let Ok(sink) = self.inner.read().map(|layer| Arc::clone(&layer.sink)) {
            sink.on_event(event, ctx);
        }
    }

    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) {
        let filter = self.new_span_filter(&ctx);
        let mut values = vec![None; attrs.metadata().fields().len()];
        attrs.record(&mut SpanValueVisitor {
            metadata: attrs.metadata(),
            values: &mut values,
        });
        if let Ok(mut spans) = self.spans.lock() {
            spans.insert(
                id.clone(),
                SpanState {
                    metadata: attrs.metadata(),
                    values,
                },
            );
        }
        filter.on_new_span(attrs, id, ctx.clone());
        if let Ok(sink) = self.inner.read().map(|layer| Arc::clone(&layer.sink)) {
            sink.on_new_span(attrs, id, ctx);
        }
    }

    fn on_record(
        &self,
        span: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) {
        if let Ok(mut spans) = self.spans.lock() {
            if let Some(state) = spans.get_mut(span) {
                values.record(&mut SpanValueVisitor {
                    metadata: state.metadata,
                    values: &mut state.values,
                });
            }
        }
        let filter = self.new_span_filter(&ctx);
        filter.on_record(span, values, ctx.clone());
        if let Ok(sink) = self.inner.read().map(|layer| Arc::clone(&layer.sink)) {
            sink.on_record(span, values, ctx);
        }
    }

    fn on_follows_from(
        &self,
        span: &tracing::span::Id,
        follows: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) {
        if let Ok(sink) = self.inner.read().map(|layer| Arc::clone(&layer.sink)) {
            sink.on_follows_from(span, follows, ctx);
        }
    }

    fn on_enter(
        &self,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) {
        let filter = self.new_span_filter(&ctx);
        self.replay_span(&filter, id, &ctx);
        filter.on_enter(id, ctx.clone());
        ACTIVE_SPANS.with(|active| active.borrow_mut().push(id.clone()));
        if let Ok(sink) = self.inner.read().map(|layer| Arc::clone(&layer.sink)) {
            sink.on_enter(id, ctx);
        }
    }

    fn on_exit(
        &self,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) {
        let filter = self.new_span_filter(&ctx);
        filter.on_exit(id, ctx.clone());
        ACTIVE_SPANS.with(|active| {
            let position = {
                let active = active.borrow();
                active.iter().rposition(|active_id| active_id == id)
            };
            if let Some(position) = position {
                active.borrow_mut().remove(position);
            }
        });
        if let Ok(sink) = self.inner.read().map(|layer| Arc::clone(&layer.sink)) {
            sink.on_exit(id, ctx);
        }
    }

    fn on_close(
        &self,
        id: tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, Registry>,
    ) {
        let filter = self.new_span_filter(&ctx);
        filter.on_close(id.clone(), ctx.clone());
        if let Ok(mut spans) = self.spans.lock() {
            spans.remove(&id);
        }
        if let Ok(sink) = self.inner.read().map(|layer| Arc::clone(&layer.sink)) {
            sink.on_close(id, ctx);
        }
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        None
    }
}

impl ManagedLayer {
    pub(super) fn new(
        inner: Arc<RwLock<LogConfig>>,
        callsites: Arc<Mutex<Vec<&'static tracing::Metadata<'static>>>>,
    ) -> Self {
        Self {
            inner,
            spans: Mutex::new(HashMap::new()),
            callsites,
        }
    }

    fn current_filter(&self) -> Arc<tracing_subscriber::EnvFilter> {
        self.inner
            .read()
            .map(|layer| Arc::clone(&layer.filter))
            .unwrap_or_else(|_| Arc::new(tracing_subscriber::EnvFilter::new("off")))
    }

    fn new_span_filter(
        &self,
        ctx: &tracing_subscriber::layer::Context<'_, Registry>,
    ) -> Arc<tracing_subscriber::EnvFilter> {
        let filter = self.current_filter();
        self.sync_filter(&filter, ctx);
        filter
    }

    fn sync_filter(
        &self,
        filter: &Arc<tracing_subscriber::EnvFilter>,
        ctx: &tracing_subscriber::layer::Context<'_, Registry>,
    ) {
        // EnvFilter keeps entered-span state per thread; replay it on reload.
        let changed = BOUND_FILTER.with(|bound| {
            bound
                .borrow()
                .as_ref()
                .is_none_or(|previous| !Arc::ptr_eq(previous, filter))
        });
        if !changed {
            return;
        }

        let active = ACTIVE_SPANS.with(|active| active.borrow().clone());
        let active_ids: Vec<_> = self
            .spans
            .lock()
            .map(|spans| {
                active
                    .iter()
                    .filter(|id| spans.contains_key(*id))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        for id in active_ids {
            self.replay_span(filter, &id, ctx);
            filter.on_enter(&id, ctx.clone());
        }
        BOUND_FILTER.with(|bound| *bound.borrow_mut() = Some(Arc::clone(filter)));
    }

    fn replay_span(
        &self,
        filter: &Arc<tracing_subscriber::EnvFilter>,
        id: &tracing::span::Id,
        ctx: &tracing_subscriber::layer::Context<'_, Registry>,
    ) {
        let state = self
            .spans
            .lock()
            .ok()
            .and_then(|spans| spans.get(id).cloned());
        let Some(state) = state else {
            return;
        };
        let values = state
            .values
            .iter()
            .map(|value| value.as_ref().map(StoredValue::as_value))
            .collect::<Vec<_>>();
        let value_refs = values
            .iter()
            .map(|value| {
                value
                    .as_deref()
                    .map(|value| value as &dyn tracing::field::Value)
            })
            .collect::<Vec<_>>();
        let values = state.metadata.fields().value_set_all(&value_refs);
        let attrs = tracing::span::Attributes::new(state.metadata, &values);
        filter.on_new_span(&attrs, id, ctx.clone());
    }
}

impl OwnedDispatcher {
    pub(super) fn new(inner: Arc<RwLock<LogConfig>>) -> Self {
        let callsites = Arc::new(Mutex::new(Vec::new()));
        let subscriber = Registry::default().with(ManagedLayer::new(
            Arc::clone(&inner),
            Arc::clone(&callsites),
        ));
        Self {
            inner,
            callsites,
            subscriber,
        }
    }
}

impl tracing::Subscriber for OwnedDispatcher {
    fn on_register_dispatch(&self, dispatch: &tracing::Dispatch) {
        self.subscriber.on_register_dispatch(dispatch);
    }

    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        self.subscriber.register_callsite(metadata)
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        self.subscriber.enabled(metadata)
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        self.subscriber.max_level_hint()
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        self.subscriber.new_span(span)
    }

    fn record(&self, span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        self.subscriber.record(span, values);
    }

    fn record_follows_from(&self, span: &tracing::span::Id, follows: &tracing::span::Id) {
        self.subscriber.record_follows_from(span, follows);
    }

    fn event_enabled(&self, event: &tracing::Event<'_>) -> bool {
        self.subscriber.event_enabled(event)
    }

    fn event(&self, event: &tracing::Event<'_>) {
        self.subscriber.event(event);
    }

    fn enter(&self, span: &tracing::span::Id) {
        self.subscriber.enter(span);
    }

    fn exit(&self, span: &tracing::span::Id) {
        self.subscriber.exit(span);
    }

    fn clone_span(&self, id: &tracing::span::Id) -> tracing::span::Id {
        self.subscriber.clone_span(id)
    }

    fn try_close(&self, id: tracing::span::Id) -> bool {
        self.subscriber.try_close(id)
    }

    fn current_span(&self) -> tracing_core::span::Current {
        self.subscriber.current_span()
    }
}
