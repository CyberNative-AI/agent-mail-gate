import contextlib
import io
import json
import unittest
from pathlib import Path

from agentmailgate import cli
from tests.helpers import tempdir

TOKEN = "Zq7leakcanary"


class CliErrorTests(unittest.TestCase):
    """CLI errors carry codes, positions or validated ids: never supplied text or a path."""

    def setUp(self):
        self._tmp = tempdir()
        self.tmp = Path(self._tmp.name) / f"dir-{TOKEN}"
        self.tmp.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def run_cli(self, *argv):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(list(argv))
        return code, err.getvalue()

    def config(self, text):
        path = self.tmp / "gate.toml"
        path.write_text(text)
        return str(path)

    def assertNoEcho(self, output):
        self.assertTrue(output.startswith("amg: "), output)
        self.assertNotIn(TOKEN, output)
        self.assertNotIn(str(self.tmp), output)

    def test_missing_config_names_no_path(self):
        code, err = self.run_cli("--config", str(self.tmp / "missing.toml"), "inbox")
        self.assertEqual(code, 2)
        self.assertNoEcho(err)
        self.assertIn("file_not_found", err)

    def test_malformed_config_values_are_not_echoed(self):
        for text in (f'[screening]\nowner_addresses = ["{TOKEN}"]\n',
                     f'[screening]\nprotected_domains = ["{TOKEN}!"]\n',
                     f'[screening.own_recipients]\n"{TOKEN}" = "x"\n',
                     f'[screening.own_recipients]\n"a@example.com" = "{TOKEN}!"\n',
                     f'state_dir = "{TOKEN}\n'):
            with self.subTest(text=text):
                code, err = self.run_cli("--config", self.config(text), "inbox")
                self.assertEqual(code, 2)
                self.assertNoEcho(err)

    def test_malformed_batch_and_missing_batch_are_not_echoed(self):
        cfg = self.config(f'state_dir = "{self.tmp / "state"}"\n')
        rows = [{"id": f"{TOKEN}<x>", "to": "a@example.org", "steps": [{"subject": "s", "body": "b"}]}]
        batch = self.tmp / "batch.json"
        batch.write_text(json.dumps({"version": 1, "sequenceId": "demo", "rows": rows}))
        code, err = self.run_cli("--config", cfg, "sequence", "approve", str(batch), "--not-before", "now")
        self.assertEqual(code, 2)
        self.assertNoEcho(err)
        self.assertIn("row #1", err)
        code, err = self.run_cli("--config", cfg, "sequence", "approve", str(self.tmp / "nope.json"),
                                 "--not-before", "now")
        self.assertEqual(code, 2)
        self.assertNoEcho(err)
        self.assertIn("file_not_found", err)

    def test_unsafe_state_dir_names_no_path(self):
        state = self.tmp / "state"
        state.mkdir()
        state.chmod(0o755)
        code, err = self.run_cli("--config", self.config(f'state_dir = "{state}"\n'), "inbox")
        self.assertEqual(code, 2)
        self.assertNoEcho(err)
        self.assertIn("state_dir_unsafe", err)


if __name__ == "__main__":
    unittest.main()
