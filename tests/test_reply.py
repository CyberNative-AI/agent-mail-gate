import os
import unittest
from pathlib import Path

from agentmailgate import reply
from agentmailgate.approval import ApprovalError, Approvals
from agentmailgate.screen import screen
from agentmailgate.transport import NotSent
from agentmailgate.vault import Vault, VaultError
from tests.helpers import ROOT, FakeOutbox, make_config, tempdir

MAIL = ROOT / "examples" / "mail"


class ReplyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempdir()
        self.cfg = make_config(Path(self._tmp.name))
        self.vault = Vault(self.cfg.state_dir)
        Approvals(self.cfg.state_dir).init_key()
        self.clean = screen((MAIL / "01-clean.eml").read_bytes(), self.cfg.screening)
        self.held = screen((MAIL / "02-injection.eml").read_bytes(), self.cfg.screening)
        self.vault.add(self.clean)
        self.vault.add(self.held)

    def tearDown(self):
        self._tmp.cleanup()

    def test_state_is_private_and_encrypted(self):
        for path in self.cfg.state_dir.rglob("*"):
            mode = path.stat().st_mode & 0o777
            self.assertEqual(mode, 0o700 if path.is_dir() else 0o600, path)
        self.assertNotIn(b"Dana", (self.cfg.state_dir / "vault.enc").read_bytes())

    def test_pending_hides_private_fields(self):
        rows = self.vault.pending()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all("private" not in r for r in rows))

    def test_reply_goes_to_stored_target_in_thread_once(self):
        payload = reply.approve(self.cfg, self.clean.message_ref, b"Yes, batch requests are supported.\n")
        self.assertEqual(payload["to"], "dana@example.org")
        self.assertEqual(payload["subject"], "Re: Question about your API")
        box = FakeOutbox()
        self.assertEqual(reply.send(self.cfg, self.clean.message_ref, box), "accepted")
        to, message = box.sent[0]
        self.assertEqual(to, "dana@example.org")
        self.assertEqual(message["In-Reply-To"], "<q1.abc@example.org>")
        with self.assertRaisesRegex(VaultError, "already_claimed"):
            reply.send(self.cfg, self.clean.message_ref, box)
        self.assertEqual(len(box.sent), 1)

    def test_no_reply_to_quarantined_mail(self):
        with self.assertRaisesRegex(VaultError, "withheld"):
            reply.approve(self.cfg, self.held.message_ref, b"hi")

    def test_body_edit_after_approval_refuses(self):
        reply.approve(self.cfg, self.clean.message_ref, b"approved text")
        body = self.vault.replies / f"{self.clean.message_ref}.body"
        body.write_bytes(b"different text")
        with self.assertRaisesRegex(VaultError, "changed after approval"):
            reply.send(self.cfg, self.clean.message_ref, FakeOutbox())

    def test_unapproved_reply_refuses(self):
        with self.assertRaisesRegex(ApprovalError, "not_approved"):
            reply.send(self.cfg, self.clean.message_ref, FakeOutbox())

    def test_not_sent_releases_claim(self):
        reply.approve(self.cfg, self.clean.message_ref, b"text")
        with self.assertRaises(NotSent):
            reply.send(self.cfg, self.clean.message_ref, FakeOutbox(exc=NotSent("x")))
        self.assertEqual(reply.send(self.cfg, self.clean.message_ref, FakeOutbox()), "accepted")

    def test_uncertain_send_keeps_claim(self):
        reply.approve(self.cfg, self.clean.message_ref, b"text")
        with self.assertRaises(TimeoutError):
            reply.send(self.cfg, self.clean.message_ref, FakeOutbox(exc=TimeoutError()))
        with self.assertRaisesRegex(VaultError, "already_claimed"):
            reply.send(self.cfg, self.clean.message_ref, FakeOutbox())

    def test_loose_owner_key_refuses(self):
        os.chmod(self.cfg.state_dir / "owner.key", 0o644)
        with self.assertRaisesRegex(ApprovalError, "0600"):
            reply.approve(self.cfg, self.clean.message_ref, b"text")


if __name__ == "__main__":
    unittest.main()
