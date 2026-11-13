# Design decisions

Each rule below exists because the simpler version failed, or would have, on
real mail.

## Screening is code, not a model

The first reader of a stranger's message is the most exposed. If that reader
is a model, the attacker's text is already in its context. So the first pass
is deterministic: fixed patterns, fixed limits, the same answer every time,
and a test for every rule. A model may read the result, never the raw message.

The screen is deliberately cautious. A false hold costs an owner a minute; a
false pass can cost an account. Holding is the default whenever two weak
signals line up (a lure *and* a risky link, an archive *and* an auth failure).
The `trash` verdict needs three independent signals you can see in the message
itself (dangerous attachment, lure wording, risky link) and never relies on
authentication headers, which senders can write.

## Agents see metadata for held mail, not a warning label

A held message is not shown with a warning; it is not shown at all. The
agent learns that a message from `example.net` was held for
`prompt_injection_pattern`, and nothing else. A warning label still puts the
text in front of the model.

## Links are removed from what agents read

Every link in a clean excerpt becomes `[external-link removed: host]`. An agent
that can follow links from mail can be sent anywhere. The host name keeps
enough context for a person to decide.

## Owner mail needs the provider's header, on top

Anyone can write `Authentication-Results: dmarc=pass` into a message. Receiving
providers *prepend* their own, so the topmost one is the provider's and a
sender cannot place a header above it. We trust only that header, only from
the configured authserv-id, only with `header.from` equal to the From domain,
and only when there is exactly one From header.

Verified owner mail is still screened for content. A real owner account that
has been taken over sends injection text too.

## Approvals sign bytes, not intentions

An approval is an HMAC over the sha256 of the exact message text, made with a
key agents cannot read. At send time the gateway hashes the file again. This
closes the gap where an agent edits a draft after the owner read it. It also
means there is no templating at send time: the batch file holds every final
message, so the owner reads exactly what each person will receive.

## Claim before send; an unknown outcome is final

Each send is appended to an fsynced ledger before SMTP starts. If SMTP fails
before the connection is up, the claim is released. If anything fails after,
the row is `uncertain` and is never retried automatically. A lost server reply
must not become a duplicate message to a stranger. The same rule applies to
replies: an exclusive claim file is created before sending.

## Read stops before every send

A tick reads new inbound mail before it sends. If that read fails, the tick
sends nothing. A sender that keeps sending while it cannot see replies will
mail someone who just said stop.

## Bounce and complaint matching refuses to guess

Delivery reports are messy, and the cost of a wrong match is high either way
(stopping the wrong person, or not stopping the right one). The rules:

- A report names rows by our quoted Message-ID or by its structured recipient
  fields. Free-text address search is the last resort and never matches our own
  addresses: reports routinely quote our Reply-To, and a naive scan stopped
  every row sent to that address.
- A Message-ID can be quoted text. If the report also names another batch
  recipient, both rows are held for a person instead of picking one.
- A structured field with a quoted local part, comment or escape is refused
  whole: `"sam@example.net"@evil.example` names nobody.
- Only A-Z are lowercased. Unicode case folding turns some non-ASCII letters
  into ASCII ones (long s into s), so a crafted address could name a different
  recipient.
- A helpdesk that wraps our exact subject in its own ticket subject is an
  auto-reply for that row. A bare `Re:`/`Fwd:` of our subject is a person. A
  subject shared by two rows names nobody.

## One bounce stops a row; a block on you stops the batch

A single "user unknown" says something about one address. A 5.7.1 or a
"rejected as spam" says something about *you*, and the next fifty sends will
make it worse. So a recipient bounce stops its row, while a sender block, any
complaint, or a bounce rate over the limit halts the batch.

## Resuming must name what you saw

A resume lists every open halt exactly as `status` printed it. If a new halt
arrived between your reading and your resume, the lists differ and the resume
fails. A resumed batch sends follow-ups only, never new first touches: the
owner accepted the risk for people already in the conversation, not for new
ones.

## Read-only mailbox access

The scanner uses POP and never deletes or moves mail. Held mail stays at the
provider where a person can inspect it with an ordinary client. The gateway
should never be the reason mail disappeared.
