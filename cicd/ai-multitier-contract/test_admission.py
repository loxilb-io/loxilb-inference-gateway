"""Mutation controls for the harness oracle; these are not product tests."""
import copy
import unittest

from admission import find_rule, threshold_declarations, verdict


class VerdictTests(unittest.TestCase):
    def setUp(self):
        self.body = {"serviceArguments": {"externalIP": "127.0.0.1", "port": 19100,
                     "protocol": "tcp", "mode": 4},
                     "endpoints": [{"endpointIP": "127.0.0.2", "targetPort": 8080, "weight": 1}]}
        self.empty = {"lbAttr": []}
        self.installed = {"lbAttr": [copy.deepcopy(self.body)]}

    def test_positive_control(self):
        self.assertTrue(verdict(self.body, 200, {}, self.empty, self.installed, None))

    def test_success_without_installation_fails(self):
        self.assertFalse(verdict(self.body, 200, {}, self.empty, self.empty, None))

    def test_wrong_listener_fails(self):
        self.installed["lbAttr"][0]["serviceArguments"]["port"] += 1
        self.assertFalse(verdict(self.body, 200, {}, self.empty, self.installed, None))

    def test_wrong_endpoint_fails(self):
        self.installed["lbAttr"][0]["endpoints"][0]["targetPort"] += 1
        self.assertFalse(verdict(self.body, 200, {}, self.empty, self.installed, None))

    def test_lost_argument_fails(self):
        self.body["serviceArguments"]["kvDpRankCount"] = 8
        self.assertFalse(verdict(self.body, 200, {}, self.empty, self.installed, None))

    def test_kv_numeric_zero_declarations_may_be_omitted_in_readback(self):
        for key in ("kvBlockSize", "kvZmqPort", "kvDpRankCount", "pdBootstrapPort"):
            with self.subTest(key=key):
                body = copy.deepcopy(self.body)
                body["serviceArguments"][key] = 0
                self.assertTrue(verdict(body, 200, {}, self.empty, self.installed, None))

    def test_kv_numeric_positive_declarations_must_not_be_lost(self):
        for key, value in (("kvBlockSize", 16), ("kvZmqPort", 5557),
                           ("kvDpRankCount", 1), ("pdBootstrapPort", 8998)):
            with self.subTest(key=key):
                body = copy.deepcopy(self.body)
                body["serviceArguments"][key] = value
                self.assertFalse(verdict(body, 200, {}, self.empty, self.installed, None))

    def test_ttl_zero_may_be_omitted_in_readback(self):
        self.body["serviceArguments"]["pd_session_ttl_sec"] = 0
        self.assertTrue(verdict(self.body, 200, {}, self.empty, self.installed, None))

    def test_ttl_positive_must_not_be_lost(self):
        self.body["serviceArguments"]["pd_session_ttl_sec"] = 600
        self.assertFalse(verdict(self.body, 200, {}, self.empty, self.installed, None))

    def test_ttl_declaration_must_not_be_replaced_by_effective_default(self):
        self.installed["lbAttr"][0]["serviceArguments"]["pd_session_ttl_sec"] = 300
        self.assertFalse(verdict(self.body, 200, {}, self.empty, self.installed, None))

    def test_threshold_zero_readback_means_default_declaration(self):
        rule = copy.deepcopy(self.body)
        self.assertEqual(threshold_declarations(rule), (0, 0))
        rule["serviceArguments"].update(
            pd_cache_threshold=42, pd_balance_abs_threshold=5)
        self.assertEqual(threshold_declarations(rule), (42, 5))

    def test_find_rule_requires_one_exact_composite_match(self):
        self.assertIsNotNone(find_rule(self.installed, "127.0.0.1", 19100, "tcp"))
        self.assertIsNone(find_rule(self.installed, "127.0.0.1", 19101, "tcp"))
        duplicate = {"lbAttr": [self.installed["lbAttr"][0], self.installed["lbAttr"][0]]}
        self.assertIsNone(find_rule(duplicate, "127.0.0.1", 19100, "tcp"))

    def test_unordered_readback_is_not_mutation(self):
        other = copy.deepcopy(self.body)
        other["serviceArguments"]["port"] += 1
        before = {"lbAttr": [self.body, other]}
        after = {"lbAttr": [other, self.body]}
        self.assertTrue(verdict(self.body, 400, {"error": "rank"}, before, after, "rank"))

    def test_reordering_cannot_hide_field_mutation(self):
        other = copy.deepcopy(self.body)
        before = {"lbAttr": [self.body, other]}
        after = copy.deepcopy(before)
        after["lbAttr"].reverse()
        after["lbAttr"][0]["endpoints"][0]["weight"] = 2
        self.assertFalse(verdict(self.body, 400, {"error": "rank"}, before, after, "rank"))

    def test_rejection_control(self):
        for status in (400, 422):
            self.assertTrue(verdict(self.body, status, {"message": "kvBlockSize out of range"},
                                    self.empty, self.empty, "kvBlockSize"))

    def test_wrong_reason_fails(self):
        self.assertFalse(verdict(self.body, 400, {"message": "tokenizer unavailable"},
                                 self.empty, self.empty, "reserved"))

    def test_mutation_despite_rejection_fails(self):
        self.assertFalse(verdict(self.body, 400, {"message": "kvBlockSize"},
                                 self.empty, self.installed, "kvBlockSize"))

    def test_success_status_with_error_text_fails(self):
        self.assertFalse(verdict(self.body, 200, {"message": "kvBlockSize"},
                                 self.empty, self.empty, "kvBlockSize"))

    def test_server_error_is_not_admission_pass(self):
        self.assertFalse(verdict(self.body, 500, {"message": "kvBlockSize"},
                                 self.empty, self.empty, "kvBlockSize"))


if __name__ == "__main__":
    unittest.main()
