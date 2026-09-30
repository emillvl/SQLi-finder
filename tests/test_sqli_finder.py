import unittest

from sqli_finder import (
    ResponseSnapshot,
    classify,
    mutate_parameter,
    normalize_target,
    query_parameters,
    sql_error_signatures,
)


class SQLiFinderTests(unittest.TestCase):
    def test_normalize_target_removes_fragment(self):
        self.assertEqual(
            normalize_target("https://example.test/item.php?id=5#section"),
            "https://example.test/item.php?id=5",
        )

    def test_normalize_target_rejects_non_http(self):
        with self.assertRaises(ValueError):
            normalize_target("file:///tmp/test")

    def test_query_parameters_preserves_unique_order(self):
        self.assertEqual(
            query_parameters(
                "https://example.test/view?id=1&lang=en&id=2"
            ),
            ["id", "lang"],
        )

    def test_mutate_one_parameter_only(self):
        mutated = mutate_parameter(
            "https://example.test/view?id=5&lang=en",
            "id",
        )
        self.assertIn("id=5%27", mutated)
        self.assertIn("lang=en", mutated)

    def test_detects_new_mysql_error(self):
        baseline = ResponseSnapshot(200, "Product page", False)
        probe = ResponseSnapshot(
            500,
            "You have an error in your SQL syntax near ...",
            False,
        )
        result, evidence = classify(baseline, probe)
        self.assertEqual(result, "likely")
        self.assertTrue(any("mysql" in item for item in evidence))

    def test_existing_error_is_not_new_evidence(self):
        body = "SQLSTATE[42000] generic message"
        baseline = ResponseSnapshot(200, body, False)
        probe = ResponseSnapshot(200, body, False)
        result, evidence = classify(baseline, probe)
        self.assertEqual(result, "not_detected")
        self.assertEqual(evidence, [])

    def test_possible_requires_server_error_and_size_change(self):
        baseline = ResponseSnapshot(200, "A" * 1000, False)
        probe = ResponseSnapshot(500, "B" * 2000, False)
        result, evidence = classify(baseline, probe)
        self.assertEqual(result, "possible")
        self.assertTrue(any("not proof" in item for item in evidence))

    def test_error_signature_family(self):
        self.assertIn(
            "postgresql",
            sql_error_signatures("PostgreSQL ERROR: syntax error at or near"),
        )


if __name__ == "__main__":
    unittest.main()
