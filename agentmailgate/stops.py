"""Inbound stop detection for the sequence sender.  No model, no content out.

``classify`` reads one inbound message's headers (and, for delivery and
abuse reports only, a bounded body) and returns ``[(kind, sequenceId, rowId)]``:

  replied, auto_replied, opted_out   a person or an autoresponder answered
  bounce, bounce_held                a delivery failure named the row
  sender_block                       a bounce reports a block on *us* (5.7.1,
                                     spam, reputation, policy): halt the batch
  complaint                          an abuse (feedback-loop) report
  *_unmatched                        a report or reply that names no row we
                                     can prove; kept so the miss stays visible

Matching rules, each learned from a real mistake:

* A report names its rows by our quoted Message-ID or by its structured
  recipient fields.  A free-text address scan runs only when neither exists,
  and never matches our own addresses: reports quote our Reply-To.
* A Message-ID can sit in quoted text, so it is *contested* when the report
  also names another batch recipient; every row it could mean is held for a
  person to settle instead of guessed.
* A quoted local part, comment or escape in a structured field refuses the
  whole field; ``"an@x"@y`` never names ``an@x``.
* Only A-Z are lowered.  ``casefold`` maps some non-ASCII letters onto ASCII
  ones, which could make a crafted address name a different row.
* A helpdesk that wraps our exact subject in its own is an auto-reply for that
  row; a bare ``Re:``/``Fwd:`` of our subject is a person.  A subject shared by
  two rows names nobody.
"""
from __future__ import annotations

import email
import email.policy
import re
from email.header import decode_header, make_header
from email.utils import parseaddr
from typing import Callable

Row = tuple[str, str]

DSN_CODE_FIELDS = frozenset({"status", "diagnostic-code"})
SMTP_REPLY_LINE = re.compile(r"\b[45]\d\d[ -]?[45]\.\d{1,3}\.\d{1,3}\b")
SENDER_BLOCK_CODE = re.compile(r"(?<![\d.])5\.7\.1(?!\d)")
SENDER_BLOCK_WORDS = re.compile(r"\b(spam\w*|reputation|block ?list\w*|black ?list\w*|blocked|banned|rbl|dnsbl|spamhaus"
                                r"|spamcop|barracuda|policy|policies)\b")
AUTO_SUBJECT = re.compile(r"^\s*(automatic reply|auto(matic)?[- ]?(reply|response)|out of (the )?office|autoreply|auto:)", re.I)
OPTOUT_SUBJECT = re.compile(r"\b(unsubscribe|remove me|opt[- ]?out|do not (contact|email)|stop)\b", re.I)
DAEMON_LOCALPARTS = frozenset({"mailer-daemon", "postmaster", "mail-daemon", "bounce", "bounces"})
REPORT_FIELDS = frozenset({"final-recipient", "original-recipient", "original-rcpt-to"})
ADDRESS_TOKEN = re.compile(r'[^\s<>()\[\]\\,;:"]+')
DOMAIN_PREFIX = re.compile(r"[\w.-]*")
FIELD_ADDRESS = re.compile(r"[a-z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-z0-9.-]+")
FIELD_REFUSED = frozenset('"()\\')
REPLY_PREFIX = re.compile(r"^(re|fw|fwd|aw|wg|sv|vs|tr|rif|antw|rv|res|enc)\s*(\[\d+\])?\s*:\s*", re.I)
MIN_SUBJECT_MATCH = 24

_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def ascii_lower(text: str) -> str:
    return text.translate(_ASCII_LOWER)


def address_key(address: str) -> str:
    return ascii_lower(address.strip())


def _blank_quoted_locals(text: str) -> str:
    """Blank every quoted local part so an address inside one is never a token.

    A quote followed by optional space and "@" (or "(") closes one; its span
    runs back to the previous unescaped quote, else the line start.  Spans never
    reach back past the previous span, so the scan stays linear.
    """
    spans, floor, n = [], 0, len(text)
    at = text.find('"')
    while at >= 0:
        k = at + 1
        while k < n and text[k].isspace():
            k += 1
        if k < n and text[k] in "@(":
            start = at
            while True:
                start = text.rfind('"', floor, start)
                if start <= 0 or text[start - 1] != "\\":
                    break
            if start < floor:
                start = max(floor, text.rfind("\n", floor, at) + 1)
            spans.append((start, at + 1))
            floor = at + 1
        at = text.find('"', at + 1)
    if not spans:
        return text
    out, last = [], 0
    for start, end in spans:
        out += [text[last:start], " "]
        last = end
    out.append(text[last:])
    return "".join(out)


def address_tokens(text: str) -> set[str]:
    """Whole addresses in ASCII-lowered free text."""
    found = set()
    for token in ADDRESS_TOKEN.findall(_blank_quoted_locals(text)):
        if token.count("@") != 1:
            continue
        if len(token) > 2 and token[0] == token[-1] and token[0] in "'`":
            token = token[1:-1]
        local, rest = token.split("@")
        domain = DOMAIN_PREFIX.match(rest).group()
        if not rest[len(domain):].isascii():
            continue
        domain = domain.rstrip(".")
        if local and domain and domain[0] != ".":
            found.add(local + "@" + domain)
    return found


def _field_address(value: str) -> str:
    value = value.strip()
    if value[:1] == "<" and value[-1:] == ">":
        value = value[1:-1].strip()
    return value if FIELD_ADDRESS.fullmatch(value) else ""


def _unfolded_fields(text: str, names: frozenset[str]) -> list[str]:
    found: list[str] = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        name, colon, value = lines[i].partition(":")
        i += 1
        if not (colon and name.strip() in names):
            continue
        parts = [value]
        while i < len(lines) and lines[i][:1] in (" ", "\t"):
            parts.append(lines[i])
            i += 1
        found.append(" ".join(part.strip("\r").strip() for part in parts))
    return found


def report_recipients(text: str) -> tuple[bool, set[str], bool]:
    """(any recipient field present, addresses named, any field refused)."""
    values = _unfolded_fields(text, REPORT_FIELDS)
    found, refused = set(), False
    for value in values:
        address = _field_address(value.rpartition(";")[2]) if FIELD_REFUSED.isdisjoint(value) else ""
        if address:
            found.add(address)
        else:
            refused = True
    return bool(values), found, refused


def failed_header_addresses(value: str) -> set[str]:
    value = ascii_lower(value.replace("\r", "").replace("\n", ""))
    if not FIELD_REFUSED.isdisjoint(value):
        return set()
    return {a for a in map(_field_address, value.split(",")) if a}


def subject_key(subject: str) -> str:
    try:
        subject = str(make_header(decode_header(subject)))
    except Exception:
        pass
    return " ".join(subject.split()).casefold()


def _strip_reply_prefixes(key: str) -> str:
    while True:
        stripped = REPLY_PREFIX.sub("", key, count=1)
        if stripped == key:
            return key
        key = stripped


def _subject_match(subject: str, subjects: dict[str, list[Row]], auto: bool) -> list[tuple[str, str, str]]:
    key = subject_key(subject)
    if len(key) < MIN_SUBJECT_MATCH:
        return []
    hits = {owner for ours, owners in subjects.items() if len(ours) >= MIN_SUBJECT_MATCH and ours in key
            for owner in owners}
    if not hits:
        return []
    if len(hits) > 1:
        return [("subject_unmatched", "", "")]
    bare = _strip_reply_prefixes(key) in subjects
    return [("replied" if bare and not auto else "auto_replied", *next(iter(hits)))]


def sender_block_text(text: str) -> bool:
    return bool(SENDER_BLOCK_CODE.search(text) or SENDER_BLOCK_WORDS.search(text))


def report_codes(text: str) -> list[str]:
    return _unfolded_fields(text, DSN_CODE_FIELDS) or [l for l in text.split("\n") if SMTP_REPLY_LINE.search(l)]


def sender_block_report(text: str) -> bool:
    return any(sender_block_text(value) for value in report_codes(text))


def classify(headers: bytes, fetch_body: Callable[[], bytes], our_ids: dict[str, Row],
             recipients: dict[str, list[Row]], own: frozenset[str] = frozenset(),
             subjects: dict[str, list[Row]] | None = None) -> list[tuple[str, str, str]]:
    """Return [(kind, sequenceId, rowId)] for one inbound message.

    our_ids     our sent Message-IDs -> row
    recipients  address_key(recipient) -> rows sent to it
    own         our own sending/reply addresses (ascii-lowered)
    subjects    subject_key(first-touch subject) -> rows; used only when no
                sender or reference names a row
    """
    message = email.message_from_bytes(headers, policy=email.policy.compat32)
    sender = ascii_lower(parseaddr(str(message.get("From", "")))[1].strip())
    localpart = sender.split("@", 1)[0] if "@" in sender else ""
    content_type = str(message.get("Content-Type", "")).casefold()
    is_report = "multipart/report" in content_type
    own_id = str(message.get("Message-ID", "")).strip()
    # Our own copy (sent folder, BCC): one of our Message-IDs from our address.
    # No header the recipient controls can turn a stop into a skip.
    if own_id in our_ids and sender in own:
        return []
    refs = set(re.findall(r"<[^<>\s]{3,400}>", " ".join(str(message.get(h, "")) for h in ("In-Reply-To", "References"))))
    matched_by_ref = {our_ids[r] for r in refs if r in our_ids}

    def from_body(kind: str) -> list[tuple[str, str, str]]:
        try:
            body = fetch_body()
        except Exception:
            return [(kind + "_unmatched", "", "")]
        if kind == "bounce" and re.search(rb"(?im)^action:\s*delayed\b", body) and not re.search(rb"(?im)^action:\s*failed\b", body):
            return []
        by_id = {our_ids[r] for r in our_ids if r.encode() in body}
        text = ascii_lower(body.decode("utf-8", "replace"))
        failed_header = str(message.get("X-Failed-Recipients", "")).strip()
        fields_present, fields, refused = report_recipients(text)
        failed_named = failed_header_addresses(failed_header)
        refused = refused or bool(failed_header and not failed_named)
        named = failed_named | fields
        hits: set[Row] = set()
        for failed in named:
            hits.update(recipients.get(failed, []))
        held: set[Row] = set()
        if by_id and not by_id <= hits:
            mentioned = named | (address_tokens(text) - own)
            contesting = {row for address in mentioned if recipients.get(address) and by_id.isdisjoint(recipients[address])
                          for row in recipients[address]}
            if contesting:
                held = (by_id | contesting) - hits
            else:
                hits |= by_id
        if not hits and not named and not failed_header and not fields_present and not by_id:
            for address in address_tokens(text) - own:
                hits.update(recipients.get(address, []))
        if not hits and not held:
            return [(kind + "_unmatched", "", "")]
        unnamed = refused or (kind == "complaint" and bool(held))
        events = [(kind, seq, row) for seq, row in sorted(hits)]
        if kind == "bounce":
            events += [("bounce_held", seq, row) for seq, row in sorted(held)]
            if sender_block_report(text):
                events += [("sender_block", seq, "") for seq in sorted({seq for seq, _r in hits | held})]
        return events + ([(kind + "_unmatched", "", "")] if unnamed else [])

    if is_report and "feedback-report" in content_type:
        return from_body("complaint")
    if (is_report and "delivery-status" in content_type) or localpart in DAEMON_LOCALPARTS:
        return from_body("bounce")
    owners = set(matched_by_ref) | set(recipients.get(sender, []))
    subject = str(message.get("Subject", ""))
    auto = (str(message.get("Auto-Submitted", "no")).strip().casefold() not in ("", "no")
            or message.get("X-Autoreply") is not None or message.get("X-Autorespond") is not None
            or str(message.get("Precedence", "")).strip().casefold() in ("auto_reply", "bulk", "junk")
            or AUTO_SUBJECT.search(subject) is not None)
    if not owners:
        if subjects and sender not in own:
            return _subject_match(subject, subjects, auto)
        return []
    kind = "auto_replied" if auto else ("opted_out" if OPTOUT_SUBJECT.search(subject) else "replied")
    return [(kind, seq, row) for seq, row in sorted(owners)]
