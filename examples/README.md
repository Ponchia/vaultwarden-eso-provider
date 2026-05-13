# Examples

This directory contains optional observability examples that are not installed
by the Helm chart.

- `grafana/vaultwarden-eso-provider-dashboard.json`: importable Grafana dashboard
  for the provider's redacted Prometheus metrics.
- `prometheus/vaultwarden-eso-provider-rules.yaml`: Prometheus Operator
  `PrometheusRule` starting point for readiness, error-rate, cache, and latency
  alerts.

Review labels, datasource names, alert severities, and routing before applying
these examples to a real cluster.
