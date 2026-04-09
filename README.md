# StreamTrace

**An open forensic runtime for reconstructing what actually happened.**

Your systems already know the truth.
They just say it in different languages.

StreamTrace ingests raw machine exhaust — logs, events, traces, webhooks — and turns it into a unified, defensible timeline across systems.

No vendor lock-in.
No black box.
No guessing.

---

## What This Is

StreamTrace is not:

* a SIEM
* an observability dashboard
* another “AI analytics platform”

StreamTrace is:

> **A system for reconstructing reality from fragmented data.**

It answers:

* What actually happened?
* In what order?
* Across which systems?
* With what evidence?
* Can we prove it?

---

## Why This Exists

Most tools optimize for:

* uptime
* alerts
* dashboards
* summaries

They do not optimize for truth.

When something breaks — or gets exploited — teams still:

* stitch logs manually
* jump between tools
* lose context
* argue about timelines
* fail to prove causality

That’s unacceptable.

StreamTrace exists to make reconstruction:

* fast
* unified
* evidence-backed
* reproducible

---

## Core Capabilities

### 1. Ingest Anything

* JSON logs
* CSV exports
* API/webhook events
* cloud audit logs
* auth events
* application telemetry
* arbitrary data streams

If it emits events, it works.

---

### 2. Preserve Raw Evidence

Every event is stored:

* immutably
* with hashes
* with provenance

Nothing is rewritten.
Nothing is hidden.

---

### 3. Normalize Without Losing Meaning

Events are mapped into a shared forensic model:

* timestamps (occurred / observed / received)
* actors, subjects, objects
* network + device context
* source attribution

Original structure is always preserved.

---

### 4. Correlate Across Systems

Link events by:

* identity (users, accounts)
* sessions and tokens
* IPs and devices
* hosts and workloads
* custom keys

Build chains like:

```
login → token → repo access → data export
```

---

### 5. Investigate via Timeline

The primary interface is a **global timeline**:

* zoom from hours → milliseconds
* filter by entity, source, type
* stack related events
* pivot instantly

Time is the spine. Everything else hangs off it.

---

### 6. Build Cases

* pin evidence
* annotate events
* track hypotheses
* export reports

No more screenshots. No more guesswork.

---

### 7. Export Evidence

Generate:

* structured timelines
* raw event bundles
* integrity manifests
* investigation summaries

Built for:

* incident response
* postmortems
* compliance
* legal review

---

## Quick Start

### 1. Clone

```bash
git clone https://github.com/geeknik/streamtrace
cd streamtrace
```

### 2. Run

```bash
docker compose up
```

### 3. Open UI

```
http://localhost:8080
```

### 4. Send Data

```bash
curl -X POST http://localhost:8080/v1/ingest/events \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "auth.login",
    "occurred_at": "2026-04-09T12:00:00Z",
    "actor": {"id": "alice"},
    "network": {"src_ip": "203.0.113.10"}
  }'
```

Open the timeline. You’ll see it immediately.

---

## Example Use Cases

### Incident Response

Reconstruct a breach across:

* identity provider
* cloud logs
* application events
* endpoints

### SRE / Outage Analysis

Correlate:

* deploys
* errors
* traffic shifts
* queue failures

### Fraud Investigation

Track:

* account clusters
* device reuse
* payment anomalies
* session patterns

### Internal Investigations

Build a defensible timeline with:

* raw evidence
* annotations
* exportable reports

---

## Architecture (Simplified)

```
Ingestion → Raw Store → Normalize → Index → Correlate → Investigate
```

Components:

* ingest gateway
* parser/normalizer
* event index
* entity graph
* investigation API
* dashboard UI

---

## Design Principles

* **Truth > convenience**
* **Raw data is sacred**
* **Time is the source of truth**
* **Correlation beats aggregation**
* **Every view must lead to evidence**
* **No black boxes**

---

## What This Is Not

* Not a compliance checkbox
* Not a dashboard farm
* Not “AI that guesses what happened”
* Not a replacement for every tool you have

It is the layer that tells you what actually happened across them.

---

## Roadmap

### Phase 1

* ingestion
* timeline
* evidence viewer
* basic correlation
* case export

### Phase 2

* entity graph
* sequence detection
* replay mode

### Phase 3

* signed evidence bundles
* legal hold
* advanced correlation

---

## Contributing

We want:

* new parsers
* better correlation logic
* real-world datasets
* investigation workflows
* performance improvements

Open an issue. Ship a PR.

---

## Philosophy

Most systems optimize for visibility.

StreamTrace optimizes for **reality reconstruction**.

Those are not the same thing.

---

## License

[Apache 2.0](LICENSE)

---

## Final Note

Your logs are not noise.

They are fragmented truth.

StreamTrace turns them into something you can actually trust.
