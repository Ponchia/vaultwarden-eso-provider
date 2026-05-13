use std::{
    collections::BTreeMap,
    fmt::{self, Write as _},
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use http::StatusCode;

use bweso_bitwarden::BitwardenCacheMetrics;

pub(crate) const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
const HISTOGRAM_BUCKETS: [f64; 11] = [
    0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.000, 2.500, 5.000, 10.000,
];

#[derive(Debug)]
pub(crate) struct AppMetrics {
    started_at: Instant,
    start_time: SystemTime,
    inner: Mutex<MetricsInner>,
}

impl AppMetrics {
    pub(crate) fn new() -> Self {
        Self {
            started_at: Instant::now(),
            start_time: SystemTime::now(),
            inner: Mutex::default(),
        }
    }

    pub(crate) fn record_http_request(
        &self,
        method: &str,
        route: &str,
        status: StatusCode,
        duration: Duration,
    ) {
        let key = HttpMetricKey {
            method: method.to_string(),
            route: route.to_string(),
            status: status.as_u16(),
        };

        self.record(|inner| {
            inner
                .http_requests
                .entry(key)
                .or_default()
                .observe(duration);
        });
    }

    pub(crate) fn record_resolve_request(
        &self,
        status: StatusCode,
        outcome: &'static str,
        error_kind: &'static str,
        duration: Duration,
    ) {
        let key = ResolveMetricKey {
            outcome,
            error_kind,
            status: status.as_u16(),
        };

        self.record(|inner| {
            inner
                .resolve_requests
                .entry(key)
                .or_default()
                .observe(duration);
        });
    }

    pub(crate) fn render(
        &self,
        ready: bool,
        cache_metrics: Option<BitwardenCacheMetrics>,
    ) -> String {
        let mut output = String::new();
        let uptime = self.started_at.elapsed().as_secs_f64();
        let start_time = self
            .start_time
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let ready_value = u8::from(ready);

        append_line(
            &mut output,
            format_args!("# HELP bweso_build_info Bitwarden ESO Provider build information."),
        );
        append_line(&mut output, format_args!("# TYPE bweso_build_info gauge"));
        append_line(
            &mut output,
            format_args!(
                "bweso_build_info{{version=\"{}\"}} 1",
                env!("CARGO_PKG_VERSION")
            ),
        );
        append_line(
            &mut output,
            format_args!(
                "# HELP bweso_process_start_time_seconds Unix timestamp when the process started."
            ),
        );
        append_line(
            &mut output,
            format_args!("# TYPE bweso_process_start_time_seconds gauge"),
        );
        append_line(
            &mut output,
            format_args!("bweso_process_start_time_seconds {start_time}"),
        );
        append_line(
            &mut output,
            format_args!("# HELP bweso_uptime_seconds Seconds since the process started."),
        );
        append_line(
            &mut output,
            format_args!("# TYPE bweso_uptime_seconds gauge"),
        );
        append_line(
            &mut output,
            format_args!("bweso_uptime_seconds {uptime:.6}"),
        );
        append_line(
            &mut output,
            format_args!("# HELP bweso_ready Readiness state exposed by /readyz."),
        );
        append_line(&mut output, format_args!("# TYPE bweso_ready gauge"));
        append_line(&mut output, format_args!("bweso_ready {ready_value}"));

        let Some(snapshot) = self.snapshot() else {
            return output;
        };

        render_http_metrics(&mut output, &snapshot.http_requests);
        render_resolve_metrics(&mut output, &snapshot.resolve_requests);
        if let Some(cache_metrics) = cache_metrics {
            render_cache_metrics(&mut output, cache_metrics);
        }

        output
    }

    fn record(&self, update: impl FnOnce(&mut MetricsInner)) {
        match self.inner.lock() {
            Ok(mut inner) => update(&mut inner),
            Err(error) => {
                tracing::error!(%error, "metrics registry lock is poisoned");
            }
        }
    }

    fn snapshot(&self) -> Option<MetricsInner> {
        match self.inner.lock() {
            Ok(inner) => Some(inner.clone()),
            Err(error) => {
                tracing::error!(%error, "metrics registry lock is poisoned");
                None
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
struct MetricsInner {
    http_requests: BTreeMap<HttpMetricKey, HistogramValues>,
    resolve_requests: BTreeMap<ResolveMetricKey, HistogramValues>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct HttpMetricKey {
    method: String,
    route: String,
    status: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ResolveMetricKey {
    outcome: &'static str,
    error_kind: &'static str,
    status: u16,
}

#[derive(Clone, Debug, Default)]
struct HistogramValues {
    count: u64,
    sum_seconds: f64,
    buckets: [u64; HISTOGRAM_BUCKETS.len()],
}

impl HistogramValues {
    fn observe(&mut self, duration: Duration) {
        let seconds = duration.as_secs_f64();
        self.count += 1;
        self.sum_seconds += seconds;

        for (index, bucket) in HISTOGRAM_BUCKETS.iter().enumerate() {
            if seconds <= *bucket {
                self.buckets[index] += 1;
            }
        }
    }
}

fn render_http_metrics(output: &mut String, values: &BTreeMap<HttpMetricKey, HistogramValues>) {
    append_line(
        output,
        format_args!(
            "# HELP bweso_http_requests_total HTTP requests served by the provider, labeled by method, route, and status."
        ),
    );
    append_line(
        output,
        format_args!("# TYPE bweso_http_requests_total counter"),
    );

    for (key, histogram) in values {
        append_labeled_metric(
            output,
            "bweso_http_requests_total",
            &[
                ("method", &key.method),
                ("route", &key.route),
                ("status", &key.status.to_string()),
            ],
            &histogram.count.to_string(),
        );
    }

    append_line(
        output,
        format_args!(
            "# HELP bweso_http_request_duration_seconds HTTP request duration in seconds."
        ),
    );
    append_line(
        output,
        format_args!("# TYPE bweso_http_request_duration_seconds histogram"),
    );

    for (key, histogram) in values {
        append_histogram(
            output,
            "bweso_http_request_duration_seconds",
            &[
                ("method", &key.method),
                ("route", &key.route),
                ("status", &key.status.to_string()),
            ],
            histogram,
        );
    }
}

fn render_resolve_metrics(
    output: &mut String,
    values: &BTreeMap<ResolveMetricKey, HistogramValues>,
) {
    append_line(
        output,
        format_args!(
            "# HELP bweso_resolve_requests_total Secret resolution requests, labeled only by outcome, error class, and status."
        ),
    );
    append_line(
        output,
        format_args!("# TYPE bweso_resolve_requests_total counter"),
    );

    for (key, histogram) in values {
        append_labeled_metric(
            output,
            "bweso_resolve_requests_total",
            &[
                ("outcome", key.outcome),
                ("error_kind", key.error_kind),
                ("status", &key.status.to_string()),
            ],
            &histogram.count.to_string(),
        );
    }

    append_line(
        output,
        format_args!(
            "# HELP bweso_resolve_duration_seconds Secret resolution duration in seconds."
        ),
    );
    append_line(
        output,
        format_args!("# TYPE bweso_resolve_duration_seconds histogram"),
    );

    for (key, histogram) in values {
        append_histogram(
            output,
            "bweso_resolve_duration_seconds",
            &[
                ("outcome", key.outcome),
                ("error_kind", key.error_kind),
                ("status", &key.status.to_string()),
            ],
            histogram,
        );
    }
}

fn render_cache_metrics(output: &mut String, metrics: BitwardenCacheMetrics) {
    append_line(
        output,
        format_args!(
            "# HELP bweso_cache_hits_total Resolve requests served from a fresh Bitwarden sync cache."
        ),
    );
    append_line(
        output,
        format_args!("# TYPE bweso_cache_hits_total counter"),
    );
    append_line(
        output,
        format_args!("bweso_cache_hits_total {}", metrics.cache_hits),
    );

    append_line(
        output,
        format_args!(
            "# HELP bweso_cache_refreshes_total Bitwarden sync cache refresh attempts by outcome."
        ),
    );
    append_line(
        output,
        format_args!("# TYPE bweso_cache_refreshes_total counter"),
    );
    append_labeled_metric(
        output,
        "bweso_cache_refreshes_total",
        &[("outcome", "success")],
        &metrics.refresh_successes.to_string(),
    );
    append_labeled_metric(
        output,
        "bweso_cache_refreshes_total",
        &[("outcome", "failure")],
        &metrics.refresh_failures.to_string(),
    );

    if let Some(timestamp) = metrics.last_success_unix_seconds {
        append_line(
            output,
            format_args!(
                "# HELP bweso_cache_last_success_timestamp_seconds Unix timestamp of the last successful Bitwarden sync cache refresh."
            ),
        );
        append_line(
            output,
            format_args!("# TYPE bweso_cache_last_success_timestamp_seconds gauge"),
        );
        append_line(
            output,
            format_args!("bweso_cache_last_success_timestamp_seconds {timestamp}"),
        );
    }

    if let Some(age) = metrics.last_success_age_seconds {
        append_line(
            output,
            format_args!(
                "# HELP bweso_cache_last_success_age_seconds Age in seconds of the last successful Bitwarden sync cache refresh."
            ),
        );
        append_line(
            output,
            format_args!("# TYPE bweso_cache_last_success_age_seconds gauge"),
        );
        append_line(
            output,
            format_args!("bweso_cache_last_success_age_seconds {age}"),
        );
    }
}

fn append_histogram(
    output: &mut String,
    name: &str,
    labels: &[(&str, &str)],
    histogram: &HistogramValues,
) {
    for (bucket, count) in HISTOGRAM_BUCKETS.iter().zip(histogram.buckets) {
        let le = format!("{bucket:.3}");
        let count = count.to_string();
        let bucket_name = format!("{name}_bucket");
        append_labeled_metric(
            output,
            &bucket_name,
            &label_with_extra(labels, ("le", &le)),
            &count,
        );
    }

    let count = histogram.count.to_string();
    let bucket_name = format!("{name}_bucket");
    append_labeled_metric(
        output,
        &bucket_name,
        &label_with_extra(labels, ("le", "+Inf")),
        &count,
    );
    append_labeled_metric(
        output,
        &format!("{name}_sum"),
        labels,
        &format!("{:.6}", histogram.sum_seconds),
    );
    append_labeled_metric(output, &format!("{name}_count"), labels, &count);
}

fn label_with_extra<'a>(
    labels: &[(&'a str, &'a str)],
    extra: (&'a str, &'a str),
) -> Vec<(&'a str, &'a str)> {
    let mut combined = Vec::with_capacity(labels.len() + 1);
    combined.extend_from_slice(labels);
    combined.push(extra);
    combined
}

fn append_labeled_metric(output: &mut String, name: &str, labels: &[(&str, &str)], value: &str) {
    output.push_str(name);
    output.push('{');

    for (index, (label, label_value)) in labels.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }

        output.push_str(label);
        output.push_str("=\"");
        append_escaped_label_value(output, label_value);
        output.push('"');
    }

    output.push_str("} ");
    output.push_str(value);
    output.push('\n');
}

fn append_escaped_label_value(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '\\' => output.push_str(r"\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str(r"\n"),
            _ => output.push(character),
        }
    }
}

fn append_line(output: &mut String, arguments: fmt::Arguments<'_>) {
    if output.write_fmt(arguments).is_err() {
        tracing::error!("failed to write metric line");
    }
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_prometheus_label_values() {
        let mut output = String::new();

        append_labeled_metric(&mut output, "example_total", &[("label", "a\\b\"c\n")], "1");

        assert_eq!(output, "example_total{label=\"a\\\\b\\\"c\\n\"} 1\n");
    }

    #[test]
    fn histogram_renders_buckets_sum_and_count() {
        let mut histogram = HistogramValues::default();
        histogram.observe(Duration::from_millis(5));
        histogram.observe(Duration::from_secs(11));
        let mut output = String::new();

        append_histogram(
            &mut output,
            "example_duration_seconds",
            &[("route", "/v1/resolve")],
            &histogram,
        );

        assert!(output
            .contains("example_duration_seconds_bucket{route=\"/v1/resolve\",le=\"0.005\"} 1"));
        assert!(
            output.contains("example_duration_seconds_bucket{route=\"/v1/resolve\",le=\"+Inf\"} 2")
        );
        assert!(output.contains("example_duration_seconds_sum{route=\"/v1/resolve\"} 11.005000"));
        assert!(output.contains("example_duration_seconds_count{route=\"/v1/resolve\"} 2"));
    }

    #[test]
    fn histogram_includes_exact_bucket_boundary() {
        let mut histogram = HistogramValues::default();

        histogram.observe(Duration::from_millis(10));

        assert_eq!(histogram.buckets[0], 0);
        assert_eq!(histogram.buckets[1], 1);
        assert_eq!(histogram.count, 1);
    }
}
