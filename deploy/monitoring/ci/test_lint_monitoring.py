#!/usr/bin/env python3
"""
Self-tests for lint-monitoring.py: prove every gate can go red.

A gate that cannot produce an error is a checkbox, not a gate. Each test here
feeds the linter a violating fixture and asserts the specific error fires.
The package-boundary fixtures are permanent: they keep the six removed
default-profile references (four DPU/DOCA queries, the KV-agent liveness
gauge, the controller TTFT gauge) from ever being reintroduced — including as
fallbacks buried inside a larger expression.

PII detection is intentionally absent here: it declares no Prometheus family,
so there is nothing a dashboard expression could reference. Any future
loxilb_pii_* constructor would surface as an unclassified new family in the
metric-manifest contract check instead.

Run:  python3 deploy/monitoring/ci/test_lint_monitoring.py
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

spec = importlib.util.spec_from_file_location(
    "lint_monitoring", os.path.join(HERE, "lint-monitoring.py"))
lint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lint)


def dashboard_with_expr(expr):
    return {
        "title": "Fixture", "uid": "fixture-uid",
        "templating": {"list": [{"name": "instance"}]},
        "panels": [{
            "id": 1, "type": "timeseries", "title": "fixture panel",
            "datasource": {"type": "prometheus", "uid": "loxilb-prom"},
            "targets": [{"refId": "A", "expr": expr}],
            "fieldConfig": {"defaults": {"noValue": "0"}},
        }],
    }


def lint_dashboard_fixture(expr, exporter=frozenset()):
    rep = lint.Report()
    with tempfile.TemporaryDirectory() as td:
        dash_dir = os.path.join(td, "grafana", "dashboards")
        os.makedirs(dash_dir)
        with open(os.path.join(dash_dir, "fixture.json"), "w") as fh:
            json.dump(dashboard_with_expr(expr), fh)
        lint.lint_dashboards(td, set(exporter), rep)
    return rep


def lint_dashboard_fixture_with_legend(expr, legend, exporter_map):
    rep = lint.Report()
    d = dashboard_with_expr(expr)
    d["panels"][0]["targets"][0]["legendFormat"] = legend
    with tempfile.TemporaryDirectory() as td:
        dash_dir = os.path.join(td, "grafana", "dashboards")
        os.makedirs(dash_dir)
        with open(os.path.join(dash_dir, "fixture.json"), "w") as fh:
            json.dump(d, fh)
        lint.lint_dashboards(td, dict(exporter_map), rep)
    return rep


def lint_rules_fixture(rule_expr, exporter=frozenset()):
    rep = lint.Report()
    with tempfile.TemporaryDirectory() as td:
        rules_dir = os.path.join(td, "prometheus", "rules")
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, "loxilb-alerts.yml"), "w") as fh:
            fh.write("groups:\n- name: fixture\n  rules:\n"
                     "  - alert: Fixture\n"
                     f"    expr: {rule_expr}\n")
        lint.lint_rules(td, set(exporter), {}, rep)
    return rep


class BoundaryFixtures(unittest.TestCase):
    """The six removed default-profile references must never come back."""

    REMOVED_PANEL_EXPRS = [
        'doca_offload_active_flows{instance=~"$instance"}',
        'rate(doca_offload_failures_total{instance=~"$instance"}[5m])',
        'doca_ct_pipe_utilization{instance=~"$instance"}',
        'rate(doca_meter_pool_exhausted_total{instance=~"$instance"}[5m])',
        'aictrl_ttft_pred_err_ratio_p90{instance=~"$instance"}',
        'loxilb_kv_agent_up{instance=~"$instance"}',
    ]

    def test_each_removed_reference_fails(self):
        for expr in self.REMOVED_PANEL_EXPRS:
            rep = lint_dashboard_fixture(expr)
            self.assertTrue(
                any("outside the default package boundary" in e
                    for e in rep.errors),
                f"boundary gate did not fire for: {expr}")

    def test_fallback_inside_larger_expression_fails(self):
        # The exact shape that used to hide in the AI dashboard: a boundary
        # family as an `or` fallback of an otherwise legitimate query.
        expr = ('min(loxilb_kv_subscriber_connected{instance=~"$instance"}) '
                'or on() max(loxilb_kv_agent_up{instance=~"$instance"})')
        rep = lint_dashboard_fixture(
            expr, exporter={"loxilb_kv_subscriber_connected",
                            "loxilb_kv_agent_up"})
        self.assertTrue(
            any("loxilb_kv_agent_up" in e and "boundary" in e
                for e in rep.errors),
            "fallback sub-expression escaped the boundary gate")

    def test_rule_expression_fails(self):
        rep = lint_rules_fixture("loxilb_kv_agent_up == 0")
        self.assertTrue(
            any("boundary" in e for e in rep.errors),
            "boundary gate did not fire for an alert rule expr")

    def test_clean_expression_passes(self):
        rep = lint_dashboard_fixture(
            'rate(loxilb_ai_requests_total{instance=~"$instance"}[5m])',
            exporter={"loxilb_ai_requests_total"})
        self.assertFalse(rep.errors, rep.errors)


class NameResolution(unittest.TestCase):
    def test_unknown_metric_fails(self):
        rep = lint_dashboard_fixture("loxilb_no_such_family_total")
        self.assertTrue(any("unknown metric" in e for e in rep.errors))

    def test_test_file_literal_does_not_resolve(self):
        # A mock metric name that exists only in *_test.go must not make a
        # dashboard reference resolve (no manifest present, literal fallback).
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(os.path.join(td, "pkg"))
            with open(os.path.join(td, "pkg", "x_test.go"), "w") as fh:
                fh.write('package x\n\nconst n = "loxilb_mock_only_total"\n')
            names = lint.collect_exporter_metrics(td)
        self.assertNotIn("loxilb_mock_only_total", names)

    def test_nontest_literal_resolves_in_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(os.path.join(td, "pkg"))
            with open(os.path.join(td, "pkg", "x.go"), "w") as fh:
                fh.write('package x\n\nconst n = "loxilb_real_total"\n')
            names = lint.collect_exporter_metrics(td)
        self.assertIn("loxilb_real_total", names)

    def test_manifest_supplies_composed_names(self):
        # Namespace/Subsystem-composed families never appear as one literal;
        # the committed manifest is the source of truth for them.
        with tempfile.TemporaryDirectory() as td:
            mdir = os.path.join(td, "deploy", "monitoring", "manifest")
            os.makedirs(mdir)
            with open(os.path.join(mdir, "metric-manifest.json"), "w") as fh:
                json.dump({"families": [{"name": "loxilb_pd_kv_composed_total"}]}, fh)
            names = lint.collect_exporter_metrics(td)
        self.assertIn("loxilb_pd_kv_composed_total", names)

    def test_repo_manifest_resolves_composed_family(self):
        names = lint.collect_exporter_metrics(REPO)
        self.assertIn("loxilb_pd_kv_tier15_miss_reason_total", names)


class LegendValidation(unittest.TestCase):
    """A legend variable must be producible by the query (family label,
    by-clause label, or ambient label). The fixture reproduces the original
    echo-panel defect: {{rule}} on a family whose only label is result."""

    def test_legend_var_not_on_family_fails(self):
        rep = lint_dashboard_fixture_with_legend(
            'increase(loxilb_x_total{result="fail"}[5m])', "oops {{rule}}",
            {"loxilb_x_total": ["result"]})
        self.assertTrue(any("legend" in e for e in rep.errors), rep.errors)

    def test_legend_var_on_family_passes(self):
        rep = lint_dashboard_fixture_with_legend(
            'rate(loxilb_x_total[5m])', "{{result}}",
            {"loxilb_x_total": ["result"]})
        self.assertFalse(rep.errors, rep.errors)

    def test_by_clause_var_passes(self):
        rep = lint_dashboard_fixture_with_legend(
            'sum by (reason) (rate(loxilb_x_total[5m]))', "{{reason}}",
            {"loxilb_x_total": ["reason", "result"]})
        self.assertFalse(rep.errors, rep.errors)


class PromtoolRequired(unittest.TestCase):
    def test_missing_promtool_fails_when_required(self):
        r = subprocess.run(
            [sys.executable, os.path.join(HERE, "lint-monitoring.py"),
             "--require-promtool", "--promtool", "/nonexistent/promtool"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("not found but required", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
