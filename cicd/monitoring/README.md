# CICD scenario: monitoring

End-to-end validation of the shipped monitoring stack (`deploy/monitoring/`)
against a live loxilb: Prometheus scrape, metric ground-truth cross-checks,
alert behavior, and Grafana provisioning. This is Tier 1/2 of
the internal monitoring CI plan; Tier 0 (the static lint) is
`deploy/monitoring/ci/lint-monitoring.py`.

## What it validates

| Surface | Checks |
|---|---|
| Exporter | metric deltas equal driver-known ground truth: N SSE completions, M plain-JSON (non-SSE) responses on the AI rule, C held L4 connections, R server RSTs; TTFB histogram populated; management-plane REST traffic does **not** tick the L4 error signal |
| Prometheus | `up==1`, scrape-duration budget, metrics disable→enable matrix, every shipped rule + dashboard PromQL expression executes, zero alerts firing on a healthy system |
| Grafana | dashboards provisioned, datasource healthy, every panel target executes through the datasource proxy and returns data where traffic exists |

## Run (Tier 1 — per merge, `monitoring-e2e.yml`)

```sh
./config.sh && ./validation.sh; ./rmconfig.sh
```

## Run (Tier 2 — nightly, `monitoring-drill.yml`)

```sh
./config.sh && ./drill.sh && ./validation.sh; ./rmconfig.sh
```

`drill.sh` additionally drives alert fire→resolve for `LoxilbScrapeDown`,
`LoxilbL4ErrorBurst`, and `LoxilbUnhealthyEndpoints` using a generated copy of
the shipped rules with `for:` shortened to 30s (expressions unchanged; rules
restored afterwards), then runs a short soak (`SOAK_MINUTES`, default 30)
asserting no scrape gaps, flat TSDB head-series, and bounded loxilb RSS.

## Layout notes

- Prometheus + Grafana run on the **host network** via `docker-compose.ci.yml`,
  scraping the `llb1` container's docker bridge IP — the same host-local layout
  `deploy/monitoring/README.md` documents. The scrape config is generated
  (`prometheus-ci.yml`) from the shipped `prometheus.yml` with only the target
  rewritten; rules, dashboards, and provisioning are bind-mounted from
  `deploy/monitoring/` verbatim so CI validates exactly what ships.
- Requires an eBPF-capable runner (`ubuntu-22.04`); the SSE mock is shared with
  `cicd/ai-sse-quota`.
