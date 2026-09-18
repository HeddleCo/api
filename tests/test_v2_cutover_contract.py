"""Cutover-map destinations must exist on the frozen v1alpha2 services."""
import csv
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CleanCutoverContract(unittest.TestCase):
    def test_cutover_destinations_exist_on_v1alpha2(self):
        source = (ROOT / "proto/heddle/api/v1alpha2/services.proto").read_text()
        native = {
            f"{service}.{name}"
            for service, body in re.findall(r"service (\w+) \{(.*?)\n}", source, re.S)
            for name in re.findall(r"\brpc (\w+)", body)
        }
        self.assertTrue(native)
        with (ROOT / "docs/alpha-v2/cutover-map.csv").open() as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), len({row["old_rpc"] for row in rows}))
        for row in rows:
            with self.subTest(rpc=row["old_rpc"]):
                self.assertTrue(row["semantic_obligation"].strip())
                if row["status"] == "retired":
                    self.assertEqual(row["v2_rpcs"], "")
                else:
                    self.assertEqual(row["status"], "native_contract")
                    self.assertTrue(row["v2_rpcs"])
                    for route in row["v2_rpcs"].split(";"):
                        self.assertIn(route, native)
