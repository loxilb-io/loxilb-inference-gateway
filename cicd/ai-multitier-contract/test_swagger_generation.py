import copy
import json
import unittest

from verify_swagger_generation import ZERO_PATHS, extract, verify


def fixture():
    doc = {"swagger": "2.0"}
    for path in ZERO_PATHS:
        node = doc
        for key in path:
            node = node.setdefault(key, {})
        node["minimum"] = 0
    return doc


def source(original, flat):
    return "\n".join(f'{name} = json.RawMessage([]byte(`{json.dumps(doc)}`))' for name, doc in (("SwaggerJSON", original), ("FlatSwaggerJSON", flat)))


class OracleTests(unittest.TestCase):
    def setUp(self):
        self.fixed = fixture()
        self.broken = copy.deepcopy(self.fixed)
        for path in ZERO_PATHS:
            node = self.broken
            for key in path:
                node = node[key]
            del node["minimum"]
        self.before = source(self.broken, self.fixed)
        self.after = source(self.fixed, self.fixed)

    def test_real_loss_and_repair(self):
        self.assertEqual(len(verify(self.before, self.after)), 64)

    def test_description_only_drift_is_not_regression(self):
        changed = copy.deepcopy(self.fixed)
        changed["description"] = "different formatting or prose is insufficient"
        with self.assertRaises(ValueError):
            verify(source(changed, self.fixed), self.after)

    def test_missing_or_duplicate_flat_fails(self):
        for malformed in (self.before.split("\n")[0], self.before + "\n" + self.before.split("\n")[1]):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                verify(malformed, self.after)

    def test_empty_flat_fails(self):
        with self.assertRaises(ValueError):
            verify(source(self.broken, {}), source(self.fixed, {}))

    def test_mutated_flat_fails(self):
        changed = copy.deepcopy(self.fixed)
        changed["description"] = "changed"
        with self.assertRaises(ValueError):
            verify(self.before, source(self.fixed, changed))

    def test_missing_schema_is_not_missing_minimum(self):
        with self.assertRaises(ValueError):
            verify(source({"swagger": "2.0"}, self.fixed), self.after)

    def test_unrepaired_minimum_fails(self):
        with self.assertRaises(ValueError):
            verify(self.before, source(self.broken, self.fixed))

    def test_backticks_and_parentheses_inside_json(self):
        doc = {"description": 'Use `zero` and )) and "quotes" λ'}
        encoded = source(doc, doc).replace("`zero`", '` + "`" + `zero` + "`" + `')
        self.assertEqual(extract(encoded, "SwaggerJSON")[0], doc)


if __name__ == "__main__":
    unittest.main()
