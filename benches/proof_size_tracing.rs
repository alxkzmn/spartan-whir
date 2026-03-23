use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use spartan_whir::{trace_proof_size_report, ProofSizeReport};
use tracing::{
    field::{Field, Visit},
    level_filters::LevelFilter,
    span::{Attributes, Id, Record},
    subscriber::Interest,
    Dispatch, Event, Metadata, Subscriber,
};

#[derive(Debug, Clone)]
enum FieldValue {
    U64(u64),
    I64(i64),
    Bool(bool),
    Str(String),
    Debug(String),
}

impl FieldValue {
    fn render(&self) -> String {
        match self {
            Self::U64(value) => value.to_string(),
            Self::I64(value) => value.to_string(),
            Self::Bool(value) => value.to_string(),
            Self::Str(value) => value.clone(),
            Self::Debug(value) => value.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct SpanData {
    name: &'static str,
    fields: Vec<(String, FieldValue)>,
}

impl SpanData {
    fn get_field(&self, name: &str) -> Option<&FieldValue> {
        self.fields
            .iter()
            .find_map(|(field_name, value)| (field_name == name).then_some(value))
    }

    fn get_u64(&self, name: &str) -> Option<u64> {
        match self.get_field(name) {
            Some(FieldValue::U64(value)) => Some(*value),
            Some(FieldValue::I64(value)) if *value >= 0 => Some(*value as u64),
            Some(FieldValue::Str(value)) => value.parse().ok(),
            Some(FieldValue::Debug(value)) => value.parse().ok(),
            _ => None,
        }
    }

    fn get_label(&self) -> String {
        match self.get_field("component") {
            Some(FieldValue::Str(value)) => value.clone(),
            Some(value) => value.render(),
            None => self.name.to_owned(),
        }
    }

    fn size_bytes(&self) -> Option<u64> {
        self.get_u64("bytes")
            .or_else(|| self.get_u64("total_bytes"))
    }

    fn merged_with(&self, other: &Self) -> Self {
        let mut merged = self.clone();
        for (name, value) in &other.fields {
            if merged.fields.iter().all(|(existing, _)| existing != name) {
                merged.fields.push((name.clone(), value.clone()));
            }
        }
        merged
    }

    fn render_fields(&self, parent_bytes: Option<u64>, total_bytes: Option<u64>) -> String {
        let mut parts = Vec::new();
        let node_bytes = self.size_bytes();

        if let Some(total) = self.get_u64("total_bytes") {
            parts.push(format!("total_bytes: {total}"));
        } else if let Some(bytes) = self.get_u64("bytes") {
            parts.push(format!("bytes: {bytes}"));
        }

        if let (Some(bytes), Some(parent)) = (node_bytes, parent_bytes) {
            parts.push(format!(
                "pct_of_parent: {}",
                format_percent(percent(bytes, parent))
            ));
        }

        if let (Some(bytes), Some(total)) = (node_bytes, total_bytes) {
            parts.push(format!(
                "pct_of_total: {}",
                format_percent(percent(bytes, total))
            ));
        }

        for (name, value) in &self.fields {
            if matches!(name.as_str(), "component" | "bytes" | "total_bytes") {
                continue;
            }
            if name.ends_with("_x1000") || name == "pct_basis_points" {
                continue;
            }
            parts.push(format!("{name}: {}", value.render()));
        }

        parts.join(" | ")
    }
}

#[derive(Debug, Clone)]
struct SpanNode {
    data: SpanData,
    children: Vec<u64>,
}

#[derive(Default)]
struct TraceState {
    next_id: AtomicU64,
    spans: Mutex<BTreeMap<u64, SpanNode>>,
    stack: Mutex<Vec<u64>>,
    roots: Mutex<Vec<u64>>,
}

#[derive(Clone, Default)]
struct TracePrinter {
    state: Arc<TraceState>,
}

#[derive(Default)]
struct FieldVisitor {
    fields: Vec<(String, FieldValue)>,
}

impl FieldVisitor {
    fn with_existing(existing: &[(String, FieldValue)]) -> Self {
        Self {
            fields: existing.to_vec(),
        }
    }

    fn finish(self) -> Vec<(String, FieldValue)> {
        self.fields
    }

    fn record_value(&mut self, field: &Field, value: FieldValue) {
        let name = field.name().to_owned();
        if let Some((_, existing)) = self
            .fields
            .iter_mut()
            .find(|(existing_name, _)| existing_name == &name)
        {
            *existing = value;
        } else {
            self.fields.push((name, value));
        }
    }
}

impl Visit for FieldVisitor {
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, FieldValue::U64(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, FieldValue::I64(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, FieldValue::Bool(value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, FieldValue::Str(value.to_owned()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record_value(field, FieldValue::Debug(format!("{value:?}")));
    }
}

impl TracePrinter {
    fn next_span_id(&self) -> u64 {
        self.state.next_id.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn render_tree(&self) {
        let roots = self.state.roots.lock().expect("roots lock").clone();
        let spans = self.state.spans.lock().expect("span lock").clone();

        for root_id in roots {
            self.render_root(&spans, root_id);
        }
    }

    fn render_root(&self, spans: &BTreeMap<u64, SpanNode>, root_id: u64) {
        let Some(root) = spans.get(&root_id) else {
            return;
        };

        if root.data.name == "proof_size_roundtrip" && root.children.len() == 1 {
            let child_id = root.children[0];
            if let Some(summary) = spans.get(&child_id) {
                if summary.data.name == "proof_size_breakdown" {
                    let merged = root.data.merged_with(&summary.data);
                    self.print_line("", &merged.get_label(), &merged.render_fields(None, None));
                    let total_bytes = summary.data.get_u64("total_bytes");
                    self.render_children(spans, &summary.children, "", total_bytes, total_bytes);
                    return;
                }
            }
        }

        self.print_line(
            "",
            &root.data.get_label(),
            &root.data.render_fields(None, None),
        );
        let total_bytes = root.data.get_u64("total_bytes");
        let parent_bytes = root.data.size_bytes();
        self.render_children(spans, &root.children, "", parent_bytes, total_bytes);
    }

    fn render_children(
        &self,
        spans: &BTreeMap<u64, SpanNode>,
        child_ids: &[u64],
        prefix: &str,
        parent_bytes: Option<u64>,
        total_bytes: Option<u64>,
    ) {
        for (idx, child_id) in child_ids.iter().enumerate() {
            let is_last = idx + 1 == child_ids.len();
            self.render_node(spans, *child_id, prefix, is_last, parent_bytes, total_bytes);
        }
    }

    fn render_node(
        &self,
        spans: &BTreeMap<u64, SpanNode>,
        span_id: u64,
        prefix: &str,
        is_last: bool,
        parent_bytes: Option<u64>,
        total_bytes: Option<u64>,
    ) {
        let Some(node) = spans.get(&span_id) else {
            return;
        };

        let branch = if is_last { "┕━ " } else { "┝━ " };
        let fields = node.data.render_fields(parent_bytes, total_bytes);
        self.print_line(
            &format!("{prefix}{branch}"),
            &node.data.get_label(),
            &fields,
        );

        let child_prefix = if is_last {
            format!("{prefix}   ")
        } else {
            format!("{prefix}│  ")
        };
        let child_parent_bytes = node.data.size_bytes().or(parent_bytes);
        let child_total_bytes = total_bytes.or_else(|| node.data.get_u64("total_bytes"));
        self.render_children(
            spans,
            &node.children,
            &child_prefix,
            child_parent_bytes,
            child_total_bytes,
        );
    }

    fn print_line(&self, tree_prefix: &str, label: &str, fields: &str) {
        if fields.is_empty() {
            eprintln!("INFO     {tree_prefix}{label}");
        } else {
            eprintln!("INFO     {tree_prefix}{label} | {fields}");
        }
    }
}

impl Subscriber for TracePrinter {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        matches!(
            *metadata.level(),
            tracing::Level::ERROR | tracing::Level::WARN | tracing::Level::INFO
        )
    }

    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
        let mut visitor = FieldVisitor::default();
        attrs.record(&mut visitor);

        let id = self.next_span_id();
        self.state.spans.lock().expect("span lock").insert(
            id,
            SpanNode {
                data: SpanData {
                    name: attrs.metadata().name(),
                    fields: visitor.finish(),
                },
                children: Vec::new(),
            },
        );
        Id::from_u64(id)
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        let mut spans = self.state.spans.lock().expect("span lock");
        if let Some(node) = spans.get_mut(&span.into_u64()) {
            let mut visitor = FieldVisitor::with_existing(&node.data.fields);
            values.record(&mut visitor);
            node.data.fields = visitor.finish();
        }
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, _event: &Event<'_>) {}

    fn enter(&self, span: &Id) {
        let span_id = span.into_u64();
        let mut stack = self.state.stack.lock().expect("stack lock");
        let parent = stack.last().copied();

        if let Some(parent_id) = parent {
            let mut spans = self.state.spans.lock().expect("span lock");
            if let Some(parent_node) = spans.get_mut(&parent_id) {
                if !parent_node.children.contains(&span_id) {
                    parent_node.children.push(span_id);
                }
            }
        } else {
            let mut roots = self.state.roots.lock().expect("roots lock");
            if !roots.contains(&span_id) {
                roots.push(span_id);
            }
        }

        stack.push(span_id);
    }

    fn exit(&self, span: &Id) {
        let mut stack = self.state.stack.lock().expect("stack lock");
        if stack.last().copied() == Some(span.into_u64()) {
            stack.pop();
        }
    }

    fn clone_span(&self, id: &Id) -> Id {
        Id::from_u64(id.into_u64())
    }

    fn try_close(&self, id: Id) -> bool {
        let _ = self
            .state
            .spans
            .lock()
            .expect("span lock")
            .get(&id.into_u64());
        true
    }

    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::always()
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::INFO)
    }
}

pub(crate) fn emit_proof_size_roundtrip_trace(
    k: usize,
    num_constraints: usize,
    num_io: usize,
    a_terms: usize,
    b_terms: usize,
    seed: u64,
    report: &ProofSizeReport,
) {
    let printer = TracePrinter::default();
    let dispatch = Dispatch::new(printer.clone());
    tracing::dispatcher::with_default(&dispatch, || {
        let root = tracing::info_span!(
            "proof_size_roundtrip",
            k = k as u64,
            constraints = num_constraints as u64,
            num_io = num_io as u64,
            a_terms = a_terms as u64,
            b_terms = b_terms as u64,
            seed,
        );
        let _root = root.enter();
        trace_proof_size_report(report);
    });
    printer.render_tree();
}

fn percent(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (part as f64) * 100.0 / (total as f64)
    }
}

fn format_percent(value: f64) -> String {
    let mut rendered = format!("{value:.6}");
    while rendered.contains('.') && rendered.ends_with('0') {
        rendered.pop();
    }
    if rendered.ends_with('.') {
        rendered.pop();
    }
    rendered
}
