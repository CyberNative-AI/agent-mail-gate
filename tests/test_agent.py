import contextlib
import io
import json
import os
import pwd
import sys
import unittest
from pathlib import Path
from unittest import mock

from agentmailgate import agent, cli
from tests.helpers import ROOT, tempdir


class AgentBrokerTests(unittest.TestCase):
    """amg-agent runs inbox or ack on validated refs, against a fixed config, and nothing else."""

    def setUp(self):
        self._tmp = tempdir()
        self.tmp = Path(self._tmp.name)
        self.cfg = self.tmp / "gate.toml"
        text = (ROOT / "gate.example.toml").read_text()
        self.cfg.write_text(text.replace('state_dir = "state"', f'state_dir = "{self.tmp / "state"}"', 1))
        mails = sorted(str(p) for p in (ROOT / "examples" / "mail").glob("*.eml"))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["--config", str(self.cfg), "ingest", *mails]), 0)

    def tearDown(self):
        self._tmp.cleanup()

    def run_agent(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = agent.main(list(argv), config=self.cfg)
        return code, out.getvalue(), err.getvalue()

    def pending_refs(self):
        code, out, _ = self.run_agent("inbox")
        self.assertEqual(code, 0)
        return [row["messageRef"] for row in json.loads(out)]

    def test_inbox_and_ack_work(self):
        refs = self.pending_refs()
        self.assertEqual(len(refs), 5)
        code, out, _ = self.run_agent("ack", refs[0], refs[1])
        self.assertEqual((code, json.loads(out)), (0, {"acknowledged": 2}))
        self.assertEqual(self.pending_refs(), refs[2:])
        code, out, _ = self.run_agent("ack", *([refs[2]] * 2000))  # the most refs one call takes
        self.assertEqual((code, json.loads(out)), (0, {"acknowledged": 1}))

    def test_every_other_argument_list_is_refused_before_dispatch(self):
        ref = self.pending_refs()[0]
        cfg = str(self.cfg)
        cases = [
            [], ["inbox", ref], ["inbox", "--help"], ["ack"], ["ack", "-h"], ["ack", "--", ref],
            ["ack", ref, "--config", "/x/evil.toml"], ["ack", ref, "--outbox", "/x/o"],
            ["ack", ref.upper()], ["ack", ref[:-1]], ["ack", ref + "0"], ["ack", ref + "\n"],
            ["ack", f"{ref} {ref}"], ["ack", f"{ref} reply approve"], ["ack", *([ref] * 2001)],
            # what sudo's joined-text match let through to amg itself: options before the subcommand
            ["--config", f"{cfg} ack", "--config", cfg, "reply", "approve", ref, "--body-file", "/x/d"],
            ["--config", cfg, "inbox"], ["--outbox", "/x/o", "ack", ref],
            ["reply", "approve", ref, "--body-file", "/x/d"], ["reply", "send", ref],
            ["sequence", "status"], ["sequence", "tick"], ["init"], ["scan"],
            ["screen", "/x/m.eml"], ["ingest", "/x/m.eml"],
        ]
        with mock.patch.object(cli, "main", side_effect=AssertionError("dispatched")) as dispatch:
            for argv in cases:
                with self.subTest(argv=argv[:6]):
                    self.assertEqual(self.run_agent(*argv), (2, "", agent.USAGE + "\n"))
            dispatch.assert_not_called()
        self.assertIn(ref, self.pending_refs())  # nothing was acknowledged

    def test_config_comes_from_the_account_database_not_the_environment(self):
        home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        with mock.patch.dict(os.environ, {"HOME": str(self.tmp), "XDG_CONFIG_HOME": str(self.tmp)}):
            self.assertEqual(agent.config_path(), home / ".config" / "amg" / "gate.toml")

    def test_console_entry_reads_argv_and_the_fixed_config(self):
        out = io.StringIO()
        with mock.patch.object(agent, "config_path", return_value=self.cfg), \
                mock.patch.object(sys, "argv", ["amg-agent", "inbox"]), contextlib.redirect_stdout(out):
            self.assertEqual(agent.main(), 0)
        self.assertEqual(len(json.loads(out.getvalue())), 5)


if __name__ == "__main__":
    unittest.main()
