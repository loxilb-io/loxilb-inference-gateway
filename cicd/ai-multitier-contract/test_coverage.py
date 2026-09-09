import copy
import unittest

import coverage as ledger_module


class CoverageLedgerTests(unittest.TestCase):
    def setUp(self):
        self.inventory = {"fields": [{"id": "field-one"}, {"id": "field-two"}]}
        self.ledger = ledger_module.seed(self.inventory)

    def test_seed_never_claims_coverage(self):
        result = ledger_module.validate(self.inventory, self.ledger)
        self.assertEqual(result["dimensions"]["GAP"], 12)
        self.assertFalse(result["ledgerComplete"])

    def test_missing_duplicate_and_unknown_fields_fail(self):
        for mutation in ("missing", "duplicate", "unknown"):
            with self.subTest(mutation=mutation):
                ledger = copy.deepcopy(self.ledger)
                if mutation == "missing":
                    ledger["fields"].pop()
                elif mutation == "duplicate":
                    ledger["fields"].append(ledger["fields"][0])
                else:
                    ledger["fields"][0]["id"] = "unknown"
                with self.assertRaises(ValueError):
                    ledger_module.validate(self.inventory, ledger)

    def test_missing_dimension_fails(self):
        del self.ledger["fields"][0]["dimensions"]["restore"]
        with self.assertRaises(ValueError):
            ledger_module.validate(self.inventory, self.ledger)

    def test_unsubstantiated_claim_fails(self):
        for status in ("PARTIAL", "VERIFIED", "NOT_APPLICABLE"):
            self.ledger["fields"][0]["dimensions"]["admission"]["status"] = status
            with self.assertRaises(ValueError):
                ledger_module.validate(self.inventory, self.ledger)

    def test_partial_is_not_release_ready(self):
        self.ledger["fields"][0]["dimensions"]["admission"] = {
            "status": "PARTIAL", "note": "one boundary tested", "evidence": ["test_one_boundary"]}
        result = ledger_module.validate(self.inventory, self.ledger)
        self.assertFalse(result["ledgerComplete"])


if __name__ == "__main__":
    unittest.main()
