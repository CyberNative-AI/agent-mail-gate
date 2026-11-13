import unittest

from agentmailgate.stops import address_tokens, classify, failed_header_addresses, report_recipients

OUR = {"<amg.1@example.com>": ("s", "r1"), "<amg.2@example.com>": ("s", "r2")}
RCPT = {"alex@example.org": [("s", "r1")], "sam@example.net": [("s", "r2")],
        # A seed row sent to our own address (placement tests do this).
        "hello@example.com": [("s", "r3")]}
OWN = frozenset({"hello@example.com"})
SUBJECTS = {"a question about your release checks for next year": [("s", "r1")]}


def run(raw: str, subjects=None):
    data = raw.encode()
    head = data.split(b"\n\n", 1)[0] + b"\n\n"
    return classify(head, lambda: data, OUR, RCPT, OWN, subjects)


DSN = "From: MAILER-DAEMON@mx.example.org\nContent-Type: multipart/report; report-type=delivery-status\n\n"


class StopTests(unittest.TestCase):
    def test_reply_by_reference_and_by_sender(self):
        self.assertEqual(run("From: x@other.example\nIn-Reply-To: <amg.1@example.com>\nSubject: Re: hi\n\nok"),
                         [("replied", "s", "r1")])
        self.assertEqual(run("From: Sam <sam@example.net>\nSubject: hello\n\nok"), [("replied", "s", "r2")])

    def test_auto_reply_and_opt_out(self):
        self.assertEqual(run("From: sam@example.net\nAuto-Submitted: auto-replied\nSubject: x\n\n"),
                         [("auto_replied", "s", "r2")])
        self.assertEqual(run("From: sam@example.net\nSubject: Out of office\n\n"), [("auto_replied", "s", "r2")])
        self.assertEqual(run("From: sam@example.net\nSubject: please unsubscribe me\n\n"), [("opted_out", "s", "r2")])

    def test_own_copy_is_skipped_but_forged_copy_stops(self):
        self.assertEqual(run("From: hello@example.com\nMessage-ID: <amg.1@example.com>\n\n"), [])
        self.assertEqual(run("From: alex@example.org\nMessage-ID: <amg.1@example.com>\n\n"), [("replied", "s", "r1")])

    def test_bounce_by_structured_field(self):
        out = run(DSN + "Final-Recipient: rfc822; sam@example.net\nAction: failed\nStatus: 5.1.1\n")
        self.assertEqual(out, [("bounce", "s", "r2")])

    def test_delayed_dsn_is_not_a_bounce(self):
        self.assertEqual(run(DSN + "Final-Recipient: rfc822; sam@example.net\nAction: delayed\n"), [])

    def test_report_quoting_our_reply_to_does_not_stop_our_own_rows(self):
        # A report quotes our Reply-To; the free-text scan must not read that
        # as a failure for every row sent to our own address.
        out = run(DSN + "Reply-To: hello@example.com\nsomething failed for sam@example.net\n")
        self.assertEqual(out, [("bounce", "s", "r2")])

    def test_contested_message_id_holds_both_rows(self):
        out = run(DSN + "quoted: <amg.1@example.com>\nalso mentions sam@example.net\n")
        self.assertEqual(sorted(out), [("bounce_held", "s", "r1"), ("bounce_held", "s", "r2")])

    def test_quoted_local_part_names_nobody(self):
        self.assertNotIn("sam@example.net", address_tokens('"sam@example.net"@evil.example'))
        present, found, refused = report_recipients('final-recipient: rfc822; "sam@example.net"@evil.example')
        self.assertTrue(present and refused)
        self.assertEqual(found, set())
        self.assertEqual(failed_header_addresses('"a,sam@example.net"@x.example'), set())

    def test_non_ascii_letters_are_not_folded_onto_ascii(self):
        # U+017F (long s) casefolds to "s"; a crafted address in a report must
        # not name sam@example.net.
        out = run(DSN + "delivery failed for \u017fam@example.net\n")
        self.assertEqual(out, [("bounce_unmatched", "", "")])

    def test_sender_block_marks_halt(self):
        out = run(DSN + "Final-Recipient: rfc822; sam@example.net\nAction: failed\n"
                        "Diagnostic-Code: smtp; 550 5.7.1 message rejected as spam\n")
        self.assertIn(("sender_block", "s", ""), out)

    def test_complaint(self):
        out = run("From: fbl@isp.example\nContent-Type: multipart/report; report-type=feedback-report\n\n"
                  "Original-Rcpt-To: alex@example.org\n")
        self.assertEqual(out, [("complaint", "s", "r1")])

    def test_unmatched_bounce_stays_visible(self):
        self.assertEqual(run(DSN + "Final-Recipient: rfc822; nobody@example.org\n"), [("bounce_unmatched", "", "")])

    def test_helpdesk_wrapping_subject_is_auto_reply(self):
        out = run('From: support@desk.example\nSubject: Ticket created: "A question about your release checks for next year" #5\n\n',
                  SUBJECTS)
        self.assertEqual(out, [("auto_replied", "s", "r1")])
        out = run("From: someone@else.example\nSubject: RE: Fwd: A question about your release checks for next year\n\n",
                  SUBJECTS)
        self.assertEqual(out, [("replied", "s", "r1")])


if __name__ == "__main__":
    unittest.main()
