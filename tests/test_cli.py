import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from mcp_guard.cli import main

ROOT = Path(__file__).resolve().parent.parent
VULN = ROOT / "examples" / "vulnerable"
SECURE = ROOT / "examples" / "secure"
TOOLS = ROOT / "examples" / "poisoned_tools.json"


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestCli(unittest.TestCase):
    def test_vulnerable_example_fails_and_secure_passes(self):
        code, out, _ = run("scan", str(VULN))
        self.assertEqual(code, 1)
        self.assertIn("MCP008", out)
        code, out, _ = run("scan", str(SECURE))
        self.assertEqual(code, 0)
        self.assertIn("No issues found", out)

    def test_implicit_scan_subcommand(self):
        code, _, _ = run(str(SECURE))
        self.assertEqual(code, 0)

    def test_json_output(self):
        code, out, _ = run("scan", str(VULN), "-f", "json", "--fail-on", "never")
        doc = json.loads(out)
        self.assertEqual(code, 0)
        self.assertGreaterEqual(doc["summary"]["total"], 15)
        self.assertTrue(all("line" in f for f in doc["findings"]))

    def test_sarif_output_structure(self):
        _, out, _ = run("scan", str(VULN), "-f", "sarif")
        sarif = json.loads(out)
        self.assertEqual(sarif["version"], "2.1.0")
        run_ = sarif["runs"][0]
        rule_ids = [r["id"] for r in run_["tool"]["driver"]["rules"]]
        for res in run_["results"]:
            self.assertEqual(rule_ids[res["ruleIndex"]], res["ruleId"])
            self.assertIn(res["level"], ("error", "warning", "note"))
            self.assertGreaterEqual(res["locations"][0]["physicalLocation"]["region"]["startLine"], 1)

    def test_filters(self):
        _, out, _ = run("scan", str(VULN), "-f", "json", "--min-severity", "critical", "--fail-on", "never")
        self.assertTrue(all(f["severity"] == "critical" for f in json.loads(out)["findings"]))
        _, out, _ = run("scan", str(VULN), "-f", "json", "--ignore", "mcp003,MCP013", "--fail-on", "never")
        self.assertFalse({f["rule_id"] for f in json.loads(out)["findings"]} & {"MCP003", "MCP013"})

    def test_fail_on_threshold(self):
        code, _, _ = run("scan", str(VULN), "--ignore", "MCP001,MCP002,MCP005,MCP006,MCP007,MCP008,MCP009,MCP011,MCP012",
                         "--fail-on", "high")
        self.assertEqual(code, 0)  # only medium/low remain

    def test_tools_and_baseline(self):
        code, out, _ = run("tools", str(TOOLS))
        self.assertEqual(code, 1)
        for rid in ("TP001", "TP002", "TP003", "TP004", "TP005"):
            self.assertIn(rid, out)
        with tempfile.TemporaryDirectory() as d:
            base = Path(d) / "baseline.json"
            run("tools", str(TOOLS), "--save-baseline", str(base), "--fail-on", "never")
            self.assertTrue(base.exists())
            _, out, _ = run("tools", str(TOOLS), "--baseline", str(base), "-f", "json", "--fail-on", "never")
            self.assertNotIn("TP007", out)

    def test_errors(self):
        code, _, err = run("scan", "/definitely/not/here.json")
        self.assertEqual(code, 2)
        self.assertIn("no such file", err)
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "mcp.json"
            bad.write_text("{not json")
            code, _, err = run("scan", str(bad))
            self.assertEqual(code, 2)

    def test_rules_listing(self):
        code, out, _ = run("rules")
        self.assertEqual(code, 0)
        self.assertIn("MCP001", out)
        self.assertIn("TP007", out)


if __name__ == "__main__":
    unittest.main()
