import datetime as dt
import json
import os
import random
import stat
import threading
import unittest
from pathlib import Path

from agentmailgate.approval import Approvals
from agentmailgate.sequence import Engine, SequenceError, validate_batch
from agentmailgate.transport import NotSent
from agentmailgate.vault import VaultError
from tests.helpers import ROOT, Clock, FakeOutbox, make_config, tempdir

MONDAY_15Z = dt.datetime(2026, 12, 7, 15, 0, tzinfo=dt.timezone.utc)
DSN_HEAD = "From: MAILER-DAEMON@mx.example.org\nContent-Type: multipart/report; report-type=delivery-status\n\n"


def batch(rows=None, seq="demo"):
    rows = rows or [
        {"id": "r1", "to": "alex@example.org", "steps": [
            {"subject": "A question about your release checks for next year", "body": "one"},
            {"body": "two"}, {"body": "three"}]},
        {"id": "r2", "to": "sam@example.net", "steps": [
            {"subject": "A question about your scheduled jobs this winter", "body": "one"}]},
    ]
    return json.dumps({"version": 1, "sequenceId": seq, "rows": rows}).encode()


def inbound_from(messages):
    """messages: list of raw bytes; uidl = index."""
    def read(seen):
        for i, raw in enumerate(messages):
            uid = f"u{i}"
            if uid in seen:
                continue
            head = raw.split(b"\n\n", 1)[0] + b"\n\n"
            yield uid, head, (lambda r=raw: r)
    return read


class SequenceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempdir()
        self.tmp = Path(self._tmp.name)
        self.cfg = make_config(self.tmp, gap_min_s=60, gap_max_s=60)
        Approvals(self.cfg.state_dir).init_key()
        self.clock = Clock(MONDAY_15Z)
        self.outbox = FakeOutbox()
        self.mail: list[bytes] = []
        self.engine = Engine(self.cfg, self.outbox, now=self.clock, rng=random.Random(1))

    def tearDown(self):
        self._tmp.cleanup()

    def tick(self):
        return self.engine.tick(inbound_from(self.mail))

    def approve(self, data=None):
        return self.engine.approve(data or batch(), not_before=MONDAY_15Z, days=30)

    def step(self, minutes=2):
        self.clock.advance(minutes=minutes)
        return self.tick()

    # -- approval
    def test_nothing_sends_without_approval(self):
        self.assertEqual(self.tick()["result"], "idle")
        self.assertEqual(self.outbox.sent, [])

    def test_batch_edit_after_approval_refuses(self):
        self.approve()
        path = self.cfg.state_dir / "sequences" / "demo" / "batch.json"
        path.write_bytes(path.read_bytes().replace(b'"one"', b'"ONE"'))
        with self.assertRaisesRegex(SequenceError, "changed after approval"):
            self.tick()
        self.assertEqual(self.outbox.sent, [])

    def test_forged_approval_is_ignored(self):
        self.approve()
        approval = next((self.cfg.state_dir / "approvals").glob("sequence-v1-demo.json"))
        record = json.loads(approval.read_text())
        record["mac"] = "0" * 64
        approval.write_text(json.dumps(record))
        self.assertEqual(self.tick()["result"], "idle")

    def test_validate_batch_rejects_placeholders_and_extra_keys(self):
        bad = json.loads(batch())
        bad["rows"][0]["steps"][0]["body"] = "Hi {{name}}"
        with self.assertRaises(SequenceError):
            validate_batch(json.dumps(bad).encode())
        bad = json.loads(batch())
        bad["rows"][0]["cc"] = "x@example.org"
        with self.assertRaises(SequenceError):
            validate_batch(json.dumps(bad).encode())

    # -- sending
    def test_one_send_per_tick_and_gap(self):
        self.approve()
        self.assertEqual(self.tick()["result"], "sent")
        self.assertEqual(self.tick()["why"], "gap")
        self.assertEqual(self.step(minutes=1)["result"], "sent")
        self.assertEqual(len(self.outbox.sent), 2)

    def test_window_closed(self):
        self.approve()
        self.clock.t = MONDAY_15Z.replace(hour=3)
        self.assertEqual(self.tick()["why"], "window_closed")
        self.clock.t = MONDAY_15Z + dt.timedelta(days=5)  # Saturday
        self.assertEqual(self.tick()["why"], "window_closed")

    def test_followup_threads_after_business_days(self):
        self.approve()
        self.tick()
        first = self.outbox.sent[0][1]
        self.step(minutes=1)  # r2 touch 1
        self.clock.advance(days=2)  # Wednesday: 2 business days, not 3
        self.assertEqual(self.tick()["why"], "nothing_due")
        self.clock.advance(days=1)  # Thursday: 3 business days
        self.assertEqual(self.tick()["result"], "sent")
        to, follow = self.outbox.sent[-1]
        self.assertEqual(to, "alex@example.org")
        self.assertEqual(follow["Subject"], "Re: " + first["Subject"])
        self.assertEqual(follow["In-Reply-To"], first["Message-ID"])

    def test_stop_file(self):
        self.approve()
        (self.cfg.state_dir / "STOP").touch()
        self.assertEqual(self.tick()["result"], "stopped")
        (self.cfg.state_dir / "STOP").unlink()
        (self.cfg.state_dir / "stop-demo").touch()
        self.assertEqual(self.tick()["why"], "nothing_due")
        self.assertEqual(self.outbox.sent, [])

    def test_inbound_failure_blocks_sending(self):
        self.approve()

        def broken(seen):
            raise OSError("pop down")
            yield  # pragma: no cover

        self.assertEqual(self.engine.tick(broken)["result"], "no_send")
        self.assertEqual(self.outbox.sent, [])

    def test_uncertain_claim_is_never_retried(self):
        self.approve()
        self.outbox.exc = TimeoutError("lost reply")
        self.assertEqual(self.tick()["result"], "uncertain")
        self.outbox.exc = None
        self.step(minutes=5)
        self.step(minutes=5)
        self.assertEqual([to for to, _m in self.outbox.sent], ["sam@example.net"])
        self.assertEqual(self.engine.status()[0]["rows"]["uncertain"], 1)

    def test_not_sent_is_retried(self):
        self.approve()
        self.outbox.exc = NotSent("ConnectionRefusedError")
        self.assertEqual(self.tick()["result"], "not_sent")
        self.outbox.exc = None
        self.step(minutes=5)
        self.assertEqual(self.outbox.sent[0][0], "alex@example.org")

    def test_new_per_day_cap(self):
        self.cfg = make_config(self.tmp, gap_min_s=60, gap_max_s=60, new_per_day=1)
        self.engine = Engine(self.cfg, self.outbox, now=self.clock, rng=random.Random(1))
        self.approve()
        self.tick()
        self.assertEqual(self.step(minutes=5)["why"], "nothing_due")

    # -- stops and halts
    def test_reply_stops_row(self):
        self.approve()
        self.tick()
        mid = self.outbox.sent[0][1]["Message-ID"]
        self.mail.append(f"From: alex@example.org\nIn-Reply-To: {mid}\nSubject: Re: hi\n\nthanks\n".encode())
        self.clock.advance(days=7)
        self.tick()
        rows = self.engine.ledger("demo").rows()
        self.assertEqual(rows["r1"]["status"], "replied")
        self.assertNotIn("alex@example.org", [to for to, _ in self.outbox.sent[1:]])

    def test_complaint_halts_and_resume_needs_exact_halts(self):
        self.approve()
        self.tick()
        mid = self.outbox.sent[0][1]["Message-ID"]
        self.mail.append((
            "From: abuse@isp.example\nContent-Type: multipart/report; report-type=feedback-report\n\n"
            f"Feedback-Type: abuse\nOriginal-Rcpt-To: alex@example.org\nMessage-ID: {mid}\n").encode())
        self.assertEqual(self.step(minutes=5)["why"], "nothing_due")
        halts = self.engine.status()[0]["openHalts"]
        self.assertEqual([h[1] for h in halts], ["complaint"])
        with self.assertRaises(SequenceError):
            self.engine.resume("demo", [])
        self.engine.resume("demo", halts)
        self.assertEqual(self.engine.status()[0]["openHalts"], [])
        # Resumed batches send follow-ups only: r2's first touch never goes.
        self.step(minutes=5)
        self.assertNotIn("sam@example.net", [to for to, _ in self.outbox.sent])

    def test_sender_block_bounce_halts(self):
        self.approve()
        self.tick()
        mid = self.outbox.sent[0][1]["Message-ID"]
        self.mail.append((
            "From: MAILER-DAEMON@mx.example.org\nContent-Type: multipart/report; report-type=delivery-status\n\n"
            f"Final-Recipient: rfc822; alex@example.org\nAction: failed\nStatus: 5.7.1\n"
            f"Diagnostic-Code: smtp; 550 5.7.1 rejected by policy\n\n{mid}\n").encode())
        self.step(minutes=5)
        self.assertEqual([h[1] for h in self.engine.status()[0]["openHalts"]], ["sender_block"])
        self.assertEqual(len(self.outbox.sent), 1)

    def test_single_recipient_bounce_stops_only_its_row(self):
        self.approve()
        self.tick()
        self.mail.append((
            "From: MAILER-DAEMON@mx.example.org\nContent-Type: multipart/report; report-type=delivery-status\n\n"
            "Final-Recipient: rfc822; alex@example.org\nAction: failed\nStatus: 5.1.1\n"
            "Diagnostic-Code: smtp; 550 5.1.1 user unknown\n").encode())
        self.assertEqual(self.step(minutes=5)["result"], "sent")
        self.assertEqual(self.engine.ledger("demo").rows()["r1"]["status"], "bounce")
        self.assertEqual(self.engine.status()[0]["openHalts"], [])

    def test_halt_after_owner_read_voids_resume(self):
        self.approve()
        self.tick()
        self.step(minutes=5)
        mids = [m["Message-ID"] for _to, m in self.outbox.sent]
        report = ("From: abuse@isp.example\nContent-Type: multipart/report; report-type=feedback-report\n\n"
                  "Original-Rcpt-To: {to}\nMessage-ID: {mid}\n")
        self.mail.append(report.format(to="alex@example.org", mid=mids[0]).encode())
        self.step(minutes=5)
        seen_by_owner = self.engine.status()[0]["openHalts"]
        self.mail.append(report.format(to="sam@example.net", mid=mids[1]).encode())
        self.step(minutes=5)
        with self.assertRaisesRegex(SequenceError, "changed"):
            self.engine.resume("demo", seen_by_owner)


    # -- concurrency, report-read failure, pre-send opt-out and STOP admission
    def test_concurrent_ticks_admit_one_send(self):
        """Tick A pauses after choosing its step, before the claim.  Tick B,
        from another engine on the same state, must not admit any send."""
        self.cfg = make_config(self.tmp, gap_min_s=60, gap_max_s=60, new_per_day=1)
        chosen, release = threading.Event(), threading.Event()

        class PausedEngine(Engine):
            def _send(self, *args, **kwargs):
                chosen.set()
                release.wait(10)
                return super()._send(*args, **kwargs)

        a = PausedEngine(self.cfg, self.outbox, now=self.clock, rng=random.Random(1))
        b = Engine(self.cfg, self.outbox, now=self.clock, rng=random.Random(2))
        a.approve(batch(), not_before=MONDAY_15Z, days=30)
        results = {}
        worker = threading.Thread(target=lambda: results.setdefault("a", a.tick(inbound_from([]))))
        worker.start()
        self.assertTrue(chosen.wait(10))
        results["b"] = b.tick(inbound_from([]))
        try:
            b.resume("demo", [])
            resume_error = None
        except Exception as exc:  # checked after the send assertions
            resume_error = exc
        release.set()
        worker.join(10)
        self.assertEqual([to for to, _m in self.outbox.sent], ["alex@example.org"])
        self.assertEqual(results["b"], {"result": "no_send", "why": "busy"})
        self.assertEqual(results["a"]["result"], "sent")
        self.assertIsInstance(resume_error, VaultError)
        self.assertIn("busy", str(resume_error))
        # The cap still holds once the lock is free: new_per_day=1.
        self.clock.advance(minutes=5)
        self.assertEqual(b.tick(inbound_from([]))["why"], "nothing_due")
        self.assertEqual(len(self.outbox.sent), 1)

    def test_stop_file_after_tick_start_blocks_claim(self):
        state = self.cfg.state_dir

        class LateStop(Engine):  # STOP lands after the step is chosen, before the claim
            def _send(self, *args, **kwargs):
                (state / "STOP").touch()
                return super()._send(*args, **kwargs)

        engine = LateStop(self.cfg, self.outbox, now=self.clock, rng=random.Random(1))
        engine.approve(batch(), not_before=MONDAY_15Z, days=30)
        self.assertEqual(engine.tick(inbound_from([]))["result"], "stopped")
        self.assertEqual(self.outbox.sent, [])
        self.assertFalse(engine.ledger("demo").has("claim"))

    def test_state_dir_stays_private_under_common_umask(self):
        cfg = make_config(self.tmp / "fresh")
        old = os.umask(0o022)
        try:
            Approvals(cfg.state_dir).init_key()
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(cfg.state_dir.stat().st_mode), 0o700)
        Engine(cfg, self.outbox, now=self.clock)  # refused state_dir_unsafe before

    def test_report_fetch_failure_blocks_send_and_is_read_again(self):
        self.approve()
        self.tick()
        report = (DSN_HEAD + "Final-Recipient: rfc822; alex@example.org\nAction: failed\nStatus: 5.1.1\n").encode()
        head = report.split(b"\n\n", 1)[0] + b"\n\n"
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                raise ConnectionResetError("retr failed")
            return report

        def read(seen):
            if "u0" not in seen:
                yield "u0", head, flaky

        self.clock.advance(minutes=5)
        self.assertEqual(self.engine.tick(read)["why"], "inbound_read_failed:ConnectionResetError")
        self.assertEqual(len(self.outbox.sent), 1)
        self.clock.advance(minutes=5)
        self.assertEqual(self.engine.tick(read)["result"], "sent")  # r2, after the stop was applied
        self.assertEqual(self.engine.ledger("demo").rows()["r1"]["status"], "bounce")
        self.assertEqual(calls["n"], 2)

    def test_opt_out_before_first_touch_stops_row(self):
        self.approve()
        self.mail.append(b"From: Sam <sam@example.net>\nSubject: Please remove me from your list\n\nno thanks\n")
        self.assertEqual(self.tick()["result"], "sent")
        self.assertEqual(self.engine.ledger("demo").rows()["r2"]["status"], "opted_out")
        self.step(minutes=5)
        self.step(minutes=5)
        self.assertEqual([to for to, _m in self.outbox.sent], ["alex@example.org"])

    def test_ordinary_mail_before_first_touch_does_not_stop_row(self):
        self.approve()
        self.mail.append(b"From: Sam <sam@example.net>\nSubject: Your newsletter\n\nhello\n")
        self.mail.append(b"From: sam@example.net\nAuto-Submitted: auto-replied\nSubject: Unsubscribe confirmation\n\n")
        self.tick()
        self.step(minutes=5)
        self.assertEqual(sorted(to for to, _m in self.outbox.sent), ["alex@example.org", "sam@example.net"])
        # A reply to a sent row is still a reply.
        mid = self.outbox.sent[0][1]["Message-ID"]
        self.mail.append(f"From: alex@example.org\nIn-Reply-To: {mid}\nSubject: Re: hi\n\nthanks\n".encode())
        self.step(minutes=5)
        self.assertEqual(self.engine.ledger("demo").rows()["r1"]["status"], "replied")

if __name__ == "__main__":
    unittest.main()
