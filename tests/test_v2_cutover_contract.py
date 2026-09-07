"""Inventory completeness for the clean v2 cutover, independent of codegen."""
import csv
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CleanCutoverContract(unittest.TestCase):
    def test_every_existing_rpc_has_a_native_destination_or_explicit_retirement(self):
        legacy = set()
        for source in (ROOT / "proto/heddle/api/v1alpha1").glob("*.proto"):
            for service, body in re.findall(r"service (\w+) \{(.*?)\n}", source.read_text(), re.S):
                legacy.update(f"{service}.{name}" for name in re.findall(r"\brpc (\w+)", body))
        source = (ROOT / "proto/heddle/api/v2alpha1/services.proto").read_text()
        native = {
            f"{service}.{name}"
            for service, body in re.findall(r"service (\w+) \{(.*?)\n}", source, re.S)
            for name in re.findall(r"\brpc (\w+)", body)
        }
        self.assertTrue(legacy)
        self.assertTrue(native)
        with (ROOT / "docs/alpha-v2/cutover-map.csv").open() as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), len({row["old_rpc"] for row in rows}))
        self.assertEqual(legacy, {row["old_rpc"] for row in rows})
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
