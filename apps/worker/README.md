# aegis-worker

Continuously folds the runtime event stream the gateway produces into findings. Replaces
running `aegis-api process-events <source>` by hand: this is the same fold, running forever,
against whichever source the gateway is actually configured to publish to.

## Local development (file sink)

```
AEGIS_WORKER_SOURCE=file:../../.local-data/aegis-events.ndjson
AEGIS_DATABASE_URL=postgresql+asyncpg://postgres:CyberPlural2024!@localhost:5433/aegis
```

The worker tails the file, remembering how many bytes it has already consumed in a small
cursor file next to it (`<source>.cursor`) so a restart resumes instead of reprocessing the
whole capture or losing the events written while it was down.

## Production (Kafka)

```
AEGIS_WORKER_SOURCE=kafka://broker1:9092,broker2:9092/runtime-events
```

Requires the `kafka` extra: `pip install -e .[kafka]`. Consumes with a consumer group
(`AEGIS_WORKER_CONSUMER_GROUP`, default `aegis-worker`) and commits offsets only after a batch
has been durably folded into findings — at-least-once, matching the gateway's own `acks=all`
producer.

## What this does not solve

Folding the same event twice is not a no-op: `Finding.record_occurrence` has no per-event
idempotency key, only per-defect identity, so a batch that is durably committed to the
database but whose offset/cursor advance is lost to a crash gets reprocessed and its
occurrence count double-counts on restart. The window for that is one batch, not the whole
stream — processing happens before the offset commits, never after — but it is not zero. Closing
it fully needs an `event_id` column on `Occurrence`, which is a domain change, not a worker one.
