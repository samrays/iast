-- Aegis IAST ClickHouse Telemetry & Analytics Schema
-- Defines event tables, metric streams, and materialized views for high-throughput IAST telemetry.

CREATE TABLE IF NOT EXISTS runtime_events
(
    event_id            UUID,
    organization_id     UUID,
    application_id      UUID,
    environment         LowCardinality(String),
    agent_id            UUID,
    trace_id            String,
    span_id             String,
    event_type          LowCardinality(String),   -- TAINT_HIT | ATTACK | ROUTE | DEPENDENCY | CONFIG | METRIC
    rule_key            LowCardinality(String),
    severity            LowCardinality(String),
    confidence          Float32,
    route_method        LowCardinality(String),
    route_path          String,
    source_kind         LowCardinality(String),
    sink_signature      String,
    stack_fingerprint   String,
    taint_path          String,                   -- JSON, redacted
    request_summary     String,                   -- JSON, redacted
    source_ip           IPv6,
    duration_us         UInt32,
    occurred_at         DateTime64(3, 'UTC'),
    ingested_at         DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(occurred_at)
ORDER BY (organization_id, application_id, occurred_at, event_type)
TTL occurred_at + INTERVAL 30 DAY TO VOLUME 'cold',
    occurred_at + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS agent_metrics
(
    organization_id UUID,
    agent_id        UUID,
    cpu_pct         Float32,
    memory_mb       UInt32,
    events_sent     UInt32,
    events_dropped  UInt32,
    hooks_disabled  UInt16,
    observed_at     DateTime64(3, 'UTC')
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(observed_at)
ORDER BY (organization_id, agent_id, observed_at)
TTL observed_at + INTERVAL 90 DAY;

-- Rollup that powers the dashboard's finding-trend charts without scanning raw events.
CREATE MATERIALIZED VIEW IF NOT EXISTS findings_hourly
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (organization_id, application_id, rule_key, severity, hour)
AS SELECT
    organization_id, application_id, rule_key, severity,
    toStartOfHour(occurred_at) AS hour,
    count() AS hits
FROM runtime_events
WHERE event_type = 'TAINT_HIT'
GROUP BY organization_id, application_id, rule_key, severity, hour;
