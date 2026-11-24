"""Checks the generated ARM templates without deploying them.

Run: python3 -m unittest discover -s tests
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deployment"))

import build_template  # noqa: E402


class TemplateTests(unittest.TestCase):
    def setUp(self):
        self.synthetic = build_template.build("synthetic", "2030-01-01T00:00:00Z")
        self.production = build_template.build("production")

    @staticmethod
    def of_type(template, suffix):
        return [r for r in template["resources"] if r["type"].endswith(suffix)]

    def test_every_query_file_has_a_rule(self):
        files = {p.stem for p in (ROOT / "analytics").glob("*.kql")}
        self.assertEqual(files, set(build_template.RULES))

    def test_production_queries_contain_no_test_data(self):
        for rule in self.of_type(self.production, "alertRules"):
            self.assertNotIn("example.test", rule["properties"]["query"])
            self.assertFalse(rule["properties"]["displayName"].startswith("[Synthetic]"))

    def test_synthetic_queries_expire(self):
        for rule in self.of_type(self.synthetic, "alertRules"):
            self.assertIn("datetime(2030-01-01T00:00:00Z)", rule["properties"]["query"])

    def test_synthetic_entities_have_no_object_id(self):
        for rule in self.of_type(self.synthetic, "alertRules"):
            text = json.dumps(rule["properties"]["entityMappings"])
            self.assertNotIn("AadUserId", text)

    def test_subtechniques_belong_to_listed_techniques(self):
        for slug, settings in build_template.RULES.items():
            for sub in settings["sub"]:
                self.assertIn(sub.split(".")[0], settings["techniques"], slug)

    def test_automation_runs_playbook_only_for_compromise_rules(self):
        automation = self.of_type(self.production, "automationRules")[0]
        values = automation["properties"]["triggeringLogic"]["conditions"][0]["conditionProperties"]["propertyValues"]
        expected = [s for s, r in build_template.RULES.items() if r["contain"]]
        self.assertEqual(len(values), len(expected))
        self.assertNotIn("password-spray", expected)
        self.assertNotIn("new-country", expected)

    def test_playbook_defaults_to_dry_run(self):
        self.assertTrue(self.production["parameters"]["dryRun"]["defaultValue"])

    def test_synthetic_incidents_do_not_run_containment(self):
        automation = self.of_type(self.synthetic, "automationRules")[0]
        self.assertFalse(automation["properties"]["triggeringLogic"]["isEnabled"])

    def test_live_graph_writes_are_inside_explicit_allowlist(self):
        workflow = self.of_type(self.production, "workflows")[0]
        actions = workflow["properties"]["definition"]["actions"]
        group_gate = actions["For_each_account"]["actions"]["If_in_lab_group"]
        live = group_gate["actions"]["If_dry_run"]["else"]["actions"]
        allowed = live["If_explicitly_allowed"]
        self.assertEqual(set(live), {"If_explicitly_allowed"})
        self.assertIn("AllowedLabUserIds", json.dumps(allowed["expression"]))
        self.assertIn("AadUserId", json.dumps(allowed["expression"]))
        self.assertEqual(self.production["parameters"]["allowedLabUserIds"]["defaultValue"], [])
        self.assertIn("Revoke_sessions", allowed["actions"])
        self.assertIn("Disable_account", allowed["actions"])

    def test_arm_expressions_are_closed(self):
        def walk(value):
            if isinstance(value, dict):
                for item in value.values():
                    yield from walk(item)
            elif isinstance(value, list):
                for item in value:
                    yield from walk(item)
            elif isinstance(value, str) and value.startswith("[") and value.endswith("]"):
                yield value
        for expression in walk(self.production):
            self.assertEqual(expression.count("("), expression.count(")"), expression)


if __name__ == "__main__":
    unittest.main()
