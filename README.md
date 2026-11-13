# agent-mail-gate

A quarantining mail gateway for AI agents.

If your agents read and send real email, every inbound message is a prompt
written by a stranger, and every outbound message is sent in your name.
`agent-mail-gate` sits between the mailbox and the agents and handles the three
jobs we found we could not leave to a model:

1. **Inbound screening, before any model sees the mail.** Deterministic checks
   for prompt injection, credential, account and payment lures, verification
   codes, risky links, dangerous attachments, lookalike domains and spoofing of
   your own domain. Clean mail reaches agents as a bounded excerpt with every
   link removed. Held mail reaches them as metadata only: sender domain and the
   reasons, no text.
2. **Owner-approved replies.** An agent drafts. The owner approves the exact
   bytes. The gateway sends once, only to the address the screened message
   named, in the same thread.
3. **A zero-LLM sequence sender.** The owner approves a batch of exact messages.
   A timer sends them with pacing, daily caps, a send window and follow-ups in
   the same thread. Replies, opt-outs, bounces and complaints stop rows. A
   complaint, a bounce that reports a block on *you*, or a bounce rate over the
   limit halts the batch until the owner resumes it. A `STOP` file stops
   everything.

It also tells your agents when mail really comes from you: `ownerVerified` is
true only when the From address is a configured owner and your *receiving*
provider's own `Authentication-Results` header records `dmarc=pass` for that
domain. Anyone can write that header into a message; the gateway only trusts
the one your provider adds on top.

Python 3.11+, one dependency (`cryptography`), MIT licensed.

## Five-minute quickstart (no mailbox needed)

```sh
git clone https://github.com/CyberNative-AI/agent-mail-gate
cd agent-mail-gate
python3 -m venv .venv && . .venv/bin/activate
pip install .
C="--config examples/demo.toml"     # demo config: sends go to ./outbox, not the internet
```

**Screen some mail.** Five sample messages: an ordinary question, a prompt
injection, a phish with an `.exe`, a verified note from the owner, and a forged
one.

```sh
for f in examples/mail/*.eml; do amg $C screen "$f"; done
```

```text
01-clean.eml           clean       (excerpt shown, link replaced by "[external-link removed: docs.example.org]")
02-injection.eml       quarantine  ['prompt_injection_pattern']
03-phish.eml           trash       ['account_lure', 'credential_lure', 'dangerous_attachment', 'protected_domain_lookalike', 'risky_url']
04-owner-verified.eml  clean       ownerVerified: true
05-owner-spoofed.eml   quarantine  ['auth_failure', 'protected_domain_auth_failure', 'protected_domain_unverified']
```

**Store them and answer one.** `ingest` screens and stores into an encrypted
vault; `inbox` is what an agent reads.

```sh
amg $C init                                   # creates the owner key
amg $C ingest examples/mail/*.eml
amg $C inbox                                  # quarantined rows carry no text at all
REF=<messageRef of Dana's message from the inbox output>
printf 'Hi Dana,\n\nYes, the batch endpoint is supported.\n' > reply.txt   # the agent's draft
amg $C reply approve "$REF" --body-file reply.txt                       # the owner approves these bytes
amg $C --outbox outbox reply send "$REF"                                # sent once, in thread
amg $C --outbox outbox reply send "$REF"                                # refused: already_claimed
```

**Run a sequence.** Approve a batch, then tick. Each tick sends at most one
message.

```sh
amg $C sequence approve examples/batch.json --not-before now --days 30
mkdir -p inbound
amg $C --outbox outbox sequence tick --inbound-dir inbound   # first touch to alex@
amg $C --outbox outbox sequence tick --inbound-dir inbound   # first touch to sam@
cp examples/later/reply-from-alex.eml inbound/               # Alex answers
amg $C --outbox outbox sequence tick --inbound-dir inbound   # nothing_due: Alex's row stopped
amg $C sequence status                                       # r1 replied; r2 completed (it had one message)
touch demo-state/STOP
amg $C --outbox outbox sequence tick --inbound-dir inbound   # stopped
ls outbox/                                                   # the .eml files that would have gone out
```

## Running it for real

1. **Give the gateway its own Unix user** (or container). The agents must not
   be able to read its state directory, above all `owner.key`. If an agent can
   read that key, it can approve its own mail. That is the whole security model;
   see [THREAT-MODEL.md](THREAT-MODEL.md).
2. Copy `gate.example.toml` to `gate.toml` and fill in your domains, inbound
   addresses, owner address(es), your provider's authserv-id, and POP/SMTP hosts.
   Find the authserv-id in the first `Authentication-Results:` line of any mail
   your provider delivered to you (the token before the first `;`).
3. Put the mailbox login in the gateway's environment, as named by
   `user_env`/`password_env`. The config file never holds credentials.
4. Run `amg scan` on a timer (every 10-20 minutes is plenty) and, if you send
   sequences, `amg sequence tick` every two minutes.
5. Give agents a way to run `amg inbox`, `amg ack` and to write draft files, and
   nothing else. Approvals, `reply send` and `sequence` stay with the owner and
   the timer.

Example systemd user units:

```ini
# ~/.config/systemd/user/amg-scan.service
[Service]
Type=oneshot
EnvironmentFile=%h/.config/amg/mail.env
ExecStart=%h/agent-mail-gate/.venv/bin/amg --config %h/.config/amg/gate.toml scan

# ~/.config/systemd/user/amg-scan.timer
[Timer]
OnCalendar=*:0/15
[Install]
WantedBy=timers.target
```

## What agents see

`amg inbox` returns one JSON object per pending message:

```json
{
  "messageRef": "9c1e...",            // sha256; safe to log and pass around
  "disposition": "clean",
  "reasons": [],
  "senderDomain": "example.org",
  "category": "general",
  "hasAttachments": false,
  "recipient": "to:hello",            // which of your addresses, by label
  "ownerVerified": false,
  "untrustedExternalData": true,
  "from": "dana@example.org",         // clean rows only from here down
  "replyTo": "dana@example.org",
  "subject": "Question about your API",
  "date": "...",
  "excerpt": "...[external-link removed: docs.example.org]...",
  "attachmentNames": []
}
```

A quarantined row stops after `untrustedExternalData`. A clean verdict means
the text passed these checks. It does not mean the sender is who they say they
are, that they have any authority, or that the request is safe to act on.

## Sequence rules in short

- The batch file holds the exact text of every message. No templating at send
  time: what the owner approved is byte-for-byte what goes out, and a changed
  file is refused.
- Each send is written to an fsynced, append-only ledger *before* SMTP. If the
  process dies or the server's answer is lost, that row is `uncertain` and is
  never sent again automatically.
- Inbound mail is read before every send. If the read fails, nothing is sent.
- Stops: a reply, auto-reply or opt-out stops its row; a bounce stops its row.
- Halts: a complaint, a bounce that reports a block on the sender (5.7.1,
  spam, reputation, policy), or bounces at or above `bounce_halt_min` and over
  `bounce_halt_rate` halt the batch. `sequence resume` must name every open
  halt exactly as `status` shows it; a halt that arrived after you looked makes
  the resume fail. A resumed batch sends follow-ups only.
- `STOP` in the state directory stops all sending; `stop-<sequenceId>` stops one.

## Limits and non-goals

- Pattern screening catches the common attacks, not every attack. It is a
  first layer that keeps raw stranger text and live links away from your
  agents. Keep agents' tools narrow anyway.
- POP only, read-only. It never deletes or moves mail; your mail client still
  sees everything.
- Plain-text outbound only: no HTML, attachments, CC or BCC.
- It does not decide whom to email or whether a sequence is lawful where you
  send it. That is on the operator.

## About

Prepared by CyberNative AI LLC, an AI-run company, using AI agents. This is a
standalone rewrite of the screening and sending rules we use for our own
agents' mailbox; [DESIGN.md](DESIGN.md) explains why each rule exists. Issues
and pull requests are welcome.
