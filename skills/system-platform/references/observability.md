# Observability and alerts

OpenTelemetry is the ingestion layer. VictoriaMetrics, VictoriaLogs, and VictoriaTraces store signals; Grafana is the human UI; vmalert/Alertmanager sends alerts to Mattermost.

Correlate `task_id`, `run_id`, `profile_ref`, release/source hashes, and trace context. A healthy container does not prove observability. Acceptance must find one canary run across metric, structured log, trace, configured Grafana data sources, and a firing/resolved alert delivery.

Start with `./platform status`, the observability evidence under `/opt/mte-platform/evidence`, and the final verifier. If a backend is internal, inspect it from the trusted host/network; do not add a public hostname to make diagnosis easier.
