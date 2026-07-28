# Product Overview

## 1. Problem

Application security teams are drowning in unverified findings. SAST reports thousands of potential
issues with no proof any of them are reachable; DAST finds a fraction of the attack surface and cannot
say *where* in the code the flaw lives. The result is a triage backlog measured in months, developer
distrust of security tooling, and vulnerabilities that ship anyway.

Interactive Application Security Testing removes the guesswork. By instrumenting the application at
runtime, the platform observes the actual data flow of actual requests. A finding is not a hypothesis —
it is a recorded execution in which attacker-controllable data reached a dangerous operation, with the
HTTP request, the stack frames, the parameter values, and the missing sanitizer all captured.

## 2. Product thesis

> Security signal should be produced by the application itself, continuously, with proof attached.

Three consequences follow, and they define the product:

1. **Detection must be free of false positives.** Every finding carries a replayable trace. If we
   cannot show the flow, we do not report it — we report it as *observed but unconfirmed* in a separate
   confidence tier.
2. **The same instrumentation must protect, not just report.** Once the agent understands the data
   flow, blocking an in-flight exploit is a policy decision, not a new engineering problem. That is the
   ADR (Application Detection & Response) capability.
3. **Remediation, not just detection, is the deliverable.** An AI layer that has the trace, the source
   context, the framework, and the dependency graph can produce a patch a developer will actually
   merge — and explain why.

## 3. Personas

| Persona | Primary job | What they need from the platform | Primary surface |
|---|---|---|---|
| **Application security engineer** | Reduce risk across a portfolio | Portfolio risk view, policy authoring, exception workflow, compliance evidence | Security console |
| **Developer** | Ship without introducing flaws | A finding in their IDE with the exact line and a suggested patch | IDE plugin, developer dashboard, PR checks |
| **SOC analyst** | Detect and respond to attacks | Live attack feed, exploitation vs. probing, blocking, correlation with SIEM | SOC dashboard |
| **Engineering leader** | Know if security is improving | Trend of open critical risk, MTTR, coverage of the estate | Executive dashboard |
| **Compliance / GRC** | Prove control effectiveness | Findings mapped to PCI DSS, SOC 2, ISO 27001, OWASP ASVS, NIST 800-53 | Compliance dashboard, reports |
| **Platform / SRE** | Keep the estate healthy | Agent fleet health, performance overhead budget, rollout control | Agent fleet view |

## 4. Capability map

### 4.1 Detect

| Capability | Description |
|---|---|
| Runtime instrumentation | Language-native agents for Java, .NET, Node.js, Python, Go |
| Taint tracking | Source → propagator → sink dataflow with sanitizer awareness |
| Vulnerability detection engine | Rule-driven detection over taint traces and configuration state |
| Configuration & framework analysis | Insecure framework settings, missing security headers, weak crypto config |
| Dependency (SCA) discovery | Loaded libraries, versions, known CVEs, *runtime-reachable* subset |
| API discovery | Every route the agent actually observes, including undocumented ones |
| Secrets & sensitive data flow | PII/PCI/PHI classification of data crossing boundaries |

### 4.2 Understand

| Capability | Description |
|---|---|
| Call graph generation | Per-finding and per-application call graphs |
| Execution flow analyzer | Ordered trace of the exploited request |
| Risk scoring engine | Severity × exploitability × exposure × asset criticality × data sensitivity |
| AI root cause analysis | Why this flaw exists, in this codebase, in this framework |
| AI remediation generator | Concrete diff plus test, framework-idiomatic |
| Attack correlation | Group probes and exploits into campaigns across applications |

### 4.3 Respond

| Capability | Description |
|---|---|
| Attack detection engine | Payload classification at the source, exploitation confirmation at the sink |
| Application Detection & Response | Monitor / block / virtual-patch policy per rule, per application, per environment |
| Notification engine | Slack, Teams, email, webhook, PagerDuty |
| SIEM integration | Splunk, Sentinel, QRadar, Elastic, Chronicle via CEF/OCSF |

### 4.4 Govern

| Capability | Description |
|---|---|
| Multi-tenant RBAC | Organization → team → application scoping with least-privilege roles |
| Compliance mapping | OWASP Top 10, ASVS, PCI DSS 4.0, SOC 2, ISO 27001, NIST 800-53, CWE/CVSS |
| Reporting engine | Scheduled and on-demand PDF/CSV/JSON, attestation-grade |
| Audit logs | Tamper-evident record of every privileged action |
| License management | Seat and agent-count entitlement enforcement |
| Feature flags | Progressive delivery of detection rules and product features |

## 5. Competitive frame

The reference bar is **Contrast Security** for the IAST core, with dashboard expectations drawn from
Datadog, Dynatrace, Grafana, Elastic, CrowdStrike Falcon and Microsoft Defender.

| Dimension | Reference behaviour | Our position |
|---|---|---|
| Detection model | Taint tracking in-process | Same, plus explicit sanitizer-coverage scoring |
| Protection | RASP with rule-based blocking | ADR with exploitation-confirmed blocking (block only when the payload actually reached a sink) |
| AI | Assistive summaries | LangGraph agent team: RCA, remediation with tests, attack correlation, executive narrative — with human approval gates |
| Deployment | SaaS + on-prem | Kubernetes-first, air-gap capable, agent offline buffering |
| Data plane | Proprietary | OpenTelemetry-native; events queryable in ClickHouse and exportable as OCSF |

## 6. Non-functional targets

| Attribute | Target |
|---|---|
| Agent CPU overhead | < 5% p95 under normal load; hard circuit-breaker at 10% |
| Agent memory overhead | < 150 MB resident per JVM |
| Ingest throughput | 100k runtime events/sec per gateway replica |
| Finding latency | Sink hit → visible in dashboard < 10 s p95 |
| API latency | < 200 ms p95 for dashboard queries |
| Availability | 99.9% control plane; agents fully functional during control-plane outage (offline buffer ≥ 1 h) |
| Data retention | Findings indefinite; raw traces 30 d hot / 1 y cold |
| Tenant isolation | No cross-tenant read path exists in code; enforced at repository layer and verified by test |

## 7. Out of scope (deliberately)

- Network-layer WAF. The agent sits inside the application; edge filtering is a different product.
- Full static analysis of unreachable code. We report on what runs.
- Source-code hosting or SCM replacement. We integrate; we do not store repositories.
