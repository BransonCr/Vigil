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

## Docs

Architecture documentation lives in [`docs/`](./docs/).
