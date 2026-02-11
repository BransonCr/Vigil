# vigil

A network intrusion detection system (NIDS) built in Rust. Vigil monitors live network traffic, detects suspicious behavior through signature-based rules and statistical anomaly detection, and uses an LLM to generate plain-English explanations of security incidents.

## What it does

Vigil captures raw packets off a network interface, groups them into flows, and runs them through two detection layers:

- **Signatures** — rule-based detection for known attack patterns (port scans, SYN floods, DNS tunneling, etc.)
- **Anomaly detection** — statistical baselining per flow; deviations from normal behavior are flagged

When an alert is triggered, vigil calls an LLM API to produce a human-readable incident summary explaining what happened, why it's suspicious, and what to do about it.

Alerts are persisted to a local database and exposed through a REST API, with a web dashboard for real-time visibility.

## Why

Most intrusion detection tools rely entirely on static signatures — they can only catch attacks they've seen before. Vigil pairs signature matching with behavioral baselines, so novel or low-and-slow attacks that don't match any known rule can still surface as anomalies.

The LLM layer bridges the gap between raw alert data and actionable insight, making the tool useful to someone without deep packet analysis experience.

## Stack

- **Rust** — packet capture, protocol parsing, detection engine, API server
- **pcap / pnet** — raw packet capture and protocol decoding
- **tokio + axum** — async runtime and HTTP API
- **sqlx + SQLite** — alert and flow storage
- **Claude API** — LLM-powered incident summaries

## Architecture

### System context

![System context diagram](docs/system-context.png)

Vigil sits between the raw network and the analyst. It reads a continuous packet stream off the NIC in promiscuous mode, runs detection, calls the Claude API over HTTPS to enrich alerts, and serves a REST API that the web dashboard queries.

### Components

![Component diagram](docs/component.png)

The codebase is split into focused layers, each with a single responsibility. Cross-layer dependencies point at traits rather than concrete types, so each layer can be tested in isolation and new detectors or storage backends can be registered without touching existing code.

| Layer | Responsibility |
|---|---|
| **Capture** | Opens the NIC via libpcap and decodes Ethernet/IP/TCP/UDP/DNS frames into typed `Packet` values |
| **Flow** | Groups packets by 5-tuple into bidirectional `Flow` records, tracking counters, timing, and byte distribution |
| **Detection** | Runs every registered `Detector` against each `FlowSnapshot`; ships with `SignatureEngine` (rule matching) and `AnomalyDetector` (statistical baselining) |
| **Alert** | Deduplicates and prioritises raw alerts, requests an LLM summary, and hands the enriched alert to storage |
| **Enrichment** | Calls the Claude API with structured alert context and returns a plain-English incident summary |
| **Storage** | Persists alerts and flows to SQLite via sqlx |
| **API** | Serves the REST API over axum; reads from storage through the `AlertRepository` trait |

The key abstractions are four traits defined in the `Abstractions` layer:

- `PacketSource` — anything that yields packets (real NIC or a pcap replay file)
- `Detector` — anything that can inspect a `FlowSnapshot` and optionally emit a `RawAlert`
- `SummaryProvider` — anything that can turn `AlertContext` into a string
- `AlertRepository` — anything that can save and query `Alert` records

### Data model

![Data model diagram](docs/data-model.png)

| Entity | Purpose |
|---|---|
| `Packet` | A single decoded frame with addressing, protocol, TCP flags, and payload length |
| `Flow` | A bidirectional conversation identified by 5-tuple, with packet/byte counters and statistical baseline fields |
| `Alert` | A confirmed threat event linked to a flow, tagged with kind (signature or anomaly) and severity, optionally enriched with an LLM summary |
| `Signature` | A named detection rule with a category, severity, and a serialised rule DSL string |
| `AnomalyRecord` | A statistical deviation record storing the baseline value, observed value, and sigma distance |

`AlertKind` is either `SignatureMatch` or `AnomalyDetected`. `Severity` runs `Low → Medium → High → Critical`. `SignatureCategory` covers `PortScan`, `SynFlood`, `DnsTunneling`, `BruteForce`, `DataExfiltration`, and `Other`.

### Packet-to-alert pipeline

![Packet pipeline sequence diagram](docs/packet-pipeline.png)

1. `PacketCapture` reads a raw Ethernet frame from libpcap and hands it to `ProtocolParser`.
2. `ProtocolParser` decodes protocol layers and returns a typed `Packet`.
3. `FlowTracker` looks up (or creates) the matching flow by 5-tuple and updates counters and timing stats.
4. The `DetectionEngine` fans out to `SignatureEngine` and `AnomalyDetector` in parallel against a `FlowSnapshot`.
   - `SignatureEngine` evaluates each loaded rule; on a match it emits a `SignatureAlert`.
   - `AnomalyDetector` compares metrics against the stored baseline; if deviation exceeds the threshold it emits an `AnomalyAlert`.
5. `AlertManager` deduplicates the raw alerts and assigns final severity.
6. `LlmEnrichmentService` sends structured alert context to the Claude API and receives a plain-English incident summary.
7. The enriched `Alert` is inserted into SQLite.
8. Later, the REST API queries the store and returns alerts as JSON to the dashboard.
