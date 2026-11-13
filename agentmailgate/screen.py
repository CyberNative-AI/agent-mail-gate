"""Deterministic inbound screening.  No model sees a message before this runs.

``screen(raw, cfg)`` parses one RFC 5322 message and returns a ``Verdict``:

* ``clean``      bounded, link-redacted excerpt may be shown to an agent
* ``quarantine`` withheld: the agent sees metadata only (domain, flags)
* ``trash``      three independent signals agree (dangerous attachment,
                 lure wording and a risky link); still recoverable

Every field stays untrusted data.  A clean verdict says the text passed these
checks; it does not establish identity, authority or intent.  The only
identity claim the module makes is ``owner_verified``: the From address is a
configured owner AND the receiving provider (a configured authserv-id) wrote
``dmarc=pass`` for that From domain.  Sender-written Authentication-Results
headers are ignored for that decision.
"""
from __future__ import annotations

import hashlib
import html
import ipaddress
import re
from dataclasses import dataclass, replace
from email import policy
from email.header import decode_header, make_header
from email.message import Message
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import PurePosixPath
from typing import Iterable
from urllib.parse import unquote, urlsplit

from .config import Screening

ANALYSIS_CHARS = 32_000
DISPLAY_CHARS = 180
RISKY_URL_DECODE_PASSES = 2
LOOKALIKE_DISTANCE = 2

DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
# RFC 5322 dot-atom msg-id with a bounded domain literal; anything else is not
# accepted as a reply-thread anchor.
_ATEXT = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]"
RFC_MESSAGE_ID = re.compile(
    rf"<{_ATEXT}+(?:\.{_ATEXT}+)*@(?:{_ATEXT}+(?:\.{_ATEXT}+)*|\[[\x21-\x5a\x5e-\x7e]{{1,253}}\])>\Z"
)
DANGEROUS_EXTENSIONS = {
    ".bat", ".cmd", ".com", ".cpl", ".dll", ".docm", ".exe", ".hta",
    ".img", ".iso", ".jar", ".js", ".jse", ".lnk", ".msi", ".msp",
    ".pif", ".pptm", ".ps1", ".reg", ".scr", ".vbe", ".vbs", ".wsf",
    ".wsh", ".xlsm",
}
ARCHIVE_EXTENSIONS = {".7z", ".rar", ".zip"}
SHORTENER_DOMAINS = {
    "bit.ly", "cutt.ly", "is.gd", "rb.gy", "rebrand.ly", "shorturl.at",
    "tiny.cc", "tinyurl.com", "t.co",
}
PROMPT_INJECTION_PATTERNS = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"(system|developer)\s+(message|prompt)",
    r"reveal\s+(the\s+)?(secret|credential|password|token|api\s*key)",
    r"print\s+(your\s+)?(environment|env|secrets?)",
    r"run\s+(this|the following)\s+(command|script|code)",
    r"override\s+(your\s+)?(policy|rules|instructions)",
))
CREDENTIAL_LURE = re.compile(
    r"(?i)\b(password|credential|login|sign[ -]?in|verify (?:your )?account|"
    r"reset (?:your )?password|mfa|2fa|one[ -]?time code|security code)\b"
)
VERIFICATION_CODE_CONTEXT = re.compile(
    r"(?i)\b(?:"
    r"(?:verification|security|authentication|login|sign[ -]?in|one[ -]?time|single[ -]?use)"
    r"[ -]+(?:code|passcode|pin|password)|"
    r"(?:mfa|2fa|otp)(?:[ -]+(?:code|passcode|pin))?|"
    r"(?:code|passcode|pin)[ -]+(?:for|to)[ -]+(?:verify|login|sign[ -]?in|authenticate)"
    r")\b"
)
VERIFICATION_CODE_VALUE = re.compile(r"(?<!\d)\d(?:[\s-]?\d){3,7}(?!\d)")
ACCOUNT_LURE = re.compile(
    r"(?i)\b(account (?:locked|suspended|disabled|closure)|urgent action|"
    r"confirm your identity|ownership transfer|domain transfer)\b"
)
PAYMENT_LURE = re.compile(
    r"(?i)\b(wire transfer|bank details|gift cards?|crypto(?:currency)?|"
    r"payment overdue|change (?:the )?payment|invoice attached)\b"
)
ACTIVE_LINK_PATTERN = re.compile(
    r"(?i)(?<!\w)(?:(?:https?|ftps?|file|smb)://[^\s<>\"']+|mailto:[^\s<>\"']+|www\.[^\s<>\"']+)"
)
RISKY_URL_PATH_TOKENS = ("login", "verify", "password", "account", "mfa")
CONTROL_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
RECIPIENT_HEADER_FAMILIES = (("Delivered-To", "delivered-to"), ("X-Original-To", "x-original-to"), ("To", "to"))

RISK_FLAGS = frozenset({
    "account_lure", "archive_attachment", "auth_failure", "auth_triple_fail",
    "credential_lure", "dangerous_attachment", "malformed_sender",
    "message_processing_failed", "message_truncated", "payment_lure",
    "prompt_injection_pattern", "protected_domain_auth_failure",
    "protected_domain_lookalike", "protected_domain_unverified",
    "reply_to_mismatch", "risky_url", "verification_code",
})


@dataclass(frozen=True)
class Verdict:
    disposition: str            # clean | quarantine | trash
    reasons: tuple[str, ...]
    message_ref: str            # sha256 of mailbox key + Message-ID; safe to log
    from_address: str
    from_domain: str
    reply_to_address: str
    subject: str
    date: str
    excerpt: str                # empty unless disposition == clean
    attachment_names: tuple[str, ...]
    authentication: tuple[str, ...]
    category: str
    has_attachments: bool
    recipient: str              # "to:hello", "delivered-to:other", "missing", ...
    thread_message_id: str      # validated RFC Message-ID or ""
    owner_verified: bool

    def agent_view(self) -> dict:
        """What an agent may read.  Withheld verdicts carry metadata only."""
        base = {
            "messageRef": self.message_ref,
            "disposition": self.disposition,
            "reasons": list(self.reasons),
            "senderDomain": self.from_domain,
            "category": self.category,
            "hasAttachments": self.has_attachments,
            "recipient": self.recipient,
            "ownerVerified": self.owner_verified,
            "untrustedExternalData": True,
        }
        if self.disposition == "clean":
            base.update({
                "from": self.from_address,
                "replyTo": self.reply_to_address,
                "subject": self.subject,
                "date": self.date,
                "excerpt": self.excerpt,
                "attachmentNames": list(self.attachment_names),
            })
        return base


def decode_value(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def normalize_text(value: str, limit: int | None) -> str:
    value = html.unescape(value)
    value = CONTROL_PATTERN.sub(" ", value)
    value = re.sub(r"\r\n?", "\n", value)
    value = re.sub(r"[ \t]+", " ", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()[:limit]


def strip_html(value: str) -> str:
    value = re.sub(r"(?is)<(script|style|form|svg|iframe).*?>.*?</\1>", " ", value)
    value = re.sub(r"(?is)<br\s*/?>", "\n", value)
    value = re.sub(r"(?is)</p\s*>", "\n", value)
    value = re.sub(r"(?is)<[^>]+>", " ", value)
    return html.unescape(value)


def safe_domain(address: str) -> str:
    domain = address.rsplit("@", 1)[-1].lower().strip(". ") if "@" in address else ""
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return ""


def redact_urls(value: str) -> str:
    """Replace every active link with its host only, so an agent cannot follow it."""
    def replace_link(match: re.Match[str]) -> str:
        raw = match.group(0).rstrip(".,);]}")
        try:
            parseable = f"https://{raw}" if raw.lower().startswith("www.") else raw
            parsed = urlsplit(parseable)
            host = (parsed.hostname or parsed.scheme or "unknown").encode("idna").decode("ascii")
            if host.lower().startswith("www."):
                host = host[4:]
        except Exception:
            host = "invalid"
        return f"[external-link removed: {host[:120]}]"
    return ACTIVE_LINK_PATTERN.sub(replace_link, value)


def sanitize_display_text(value: str, limit: int) -> str:
    """Decode fully, then remove links, then truncate; nothing decodes after.

    Entity decoding runs first so an encoded ``https&#58;//`` is a link by the
    time redaction looks.  A final pass replaces anything that still reads as
    a link (a host label such as ``a.www.example`` would) with a fixed marker
    that cannot match.  Fields built here must not be normalized again.
    """
    text = redact_urls(normalize_text(value, max(limit, ANALYSIS_CHARS)))[:limit].strip()
    return ACTIVE_LINK_PATTERN.sub("[external-link removed]", text)


def body_texts(message: Message, excerpt_chars: int) -> tuple[str, str]:
    plain: list[str] = []
    html_parts: list[str] = []
    parts: Iterable[Message] = message.walk() if message.is_multipart() else (message,)
    for part in parts:
        if part.is_multipart() or part.get_filename():
            continue
        content_type = part.get_content_type().lower()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        if isinstance(content, str):
            (plain if content_type == "text/plain" else html_parts).append(content)
    # Classification reads every textual part, raw HTML included, so a bad href
    # cannot hide behind a harmless plain-text alternative.
    classification = normalize_text("\n".join(plain + html_parts), ANALYSIS_CHARS)
    selected = "\n".join(plain) if plain else strip_html("\n".join(html_parts))
    return classification, sanitize_display_text(selected, excerpt_chars)


def attachment_metadata(message: Message) -> tuple[tuple[str, ...], tuple[str, ...]]:
    names: list[str] = []
    suffixes: list[str] = []
    for part in message.walk():
        filename = decode_value(part.get_filename())
        disposition = (part.get_content_disposition() or "").lower()
        if not filename and disposition != "attachment":
            continue
        decoded = filename or "unnamed"
        names.append(normalize_text(decoded, 4096))
        # Judge the complete decoded name, before any truncation, both as sent
        # and entity-decoded; Windows drops trailing dots and spaces, so
        # "x.exe. " is ".exe".  A long name cannot hide ".exe".
        for candidate in (decoded, normalize_text(decoded, None)):
            tail = candidate.replace("\\", "/").rstrip(". \t")
            suffixes.append(PurePosixPath(tail).suffix.lower() if tail else "")
    return tuple(names), tuple(suffixes)


def auth_signals(message: Message) -> tuple[str, ...]:
    """Every pass/fail token in Authentication-Results and Received-SPF.

    These headers can be written by the sender, so a failure is a reason to
    hold the message but a pass never authorizes anything here.
    """
    auth_results = "\n".join(str(v) for v in message.get_all("Authentication-Results", []))
    signals: set[str] = set()
    for match in re.finditer(r"\b([a-z][a-z0-9_-]{1,31})\s*=\s*(pass|fail|softfail|permerror|temperror)\b",
                             auth_results, re.IGNORECASE):
        signals.add(f"{match.group(1).lower()}_{'pass' if match.group(2).lower() == 'pass' else 'fail'}")
    for header in message.get_all("Received-SPF", []):
        match = re.match(r"\s*(pass|fail|softfail|permerror|temperror)\b", str(header), re.IGNORECASE)
        if match:
            signals.add(f"spf_{'pass' if match.group(1).lower() == 'pass' else 'fail'}")
    return tuple(sorted(signals))


def provider_dmarc_pass(message: Message, from_domain: str, trusted_ids: Iterable[str]) -> bool:
    """True when the *topmost* Authentication-Results header is from a trusted
    authserv-id and records dmarc=pass with header.from equal to ``from_domain``.

    Receiving providers prepend their header, so the first physical one is the
    provider's.  A sender can add more below it, but cannot place one above.
    Any dmarc result other than pass in that header refuses.
    """
    trusted = {t.casefold() for t in trusted_ids}
    raw = [value for name, value in message.raw_items() if name.lower() == "authentication-results"]
    if not raw or not trusted or not from_domain:
        return False
    first = re.sub(r"\s+", " ", str(raw[0]))
    authserv = first.split(";", 1)[0].strip().split(" ", 1)[0].casefold()
    if authserv not in trusted:
        return False
    results = [m for m in re.finditer(r"\bdmarc\s*=\s*([a-z]+)\b([^;]*)", first, re.IGNORECASE)]
    if len(results) != 1 or results[0].group(1).lower() != "pass":
        return False
    header_from = re.search(r"\bheader\.from\s*=\s*([^\s;()]+)", results[0].group(2), re.IGNORECASE)
    return bool(header_from and header_from.group(1).strip().lower().rstrip(".") == from_domain)


def levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    previous = list(range(len(right) + 1))
    for i, lch in enumerate(left, 1):
        current = [i]
        for j, rch in enumerate(right, 1):
            current.append(min(current[-1] + 1, previous[j] + 1, previous[j - 1] + (lch != rch)))
        previous = current
    return previous[-1]


def risky_urls(text: str) -> bool:
    for raw in ACTIVE_LINK_PATTERN.findall(text):
        try:
            if not raw.lower().startswith(("http://", "https://")):
                return True
            parsed = urlsplit(raw)
            host = (parsed.hostname or "").lower()
            if not host:
                return True
            ascii_host = host.encode("idna").decode("ascii")
            if parsed.username or "xn--" in ascii_host:
                return True
            if any(ascii_host == d or ascii_host.endswith(f".{d}") for d in SHORTENER_DOMAINS):
                return True
            try:
                ipaddress.ip_address(ascii_host)
                return True
            except ValueError:
                pass
            parts = ascii_host.split(".")
            if parts and all(re.fullmatch(r"(?:0x[0-9a-f]+|0[0-7]+|\d+)", p, re.IGNORECASE) for p in parts):
                return True
            path = parsed.path
            for _ in range(RISKY_URL_DECODE_PASSES):
                path = unquote(path)
            if any(token in path.lower() for token in RISKY_URL_PATH_TOKENS):
                return True
        except Exception:
            return True
    return False


def recipient_observation(message: Message, own: dict[str, str]) -> str:
    """Name which of your inbound addresses the message reached, by label only."""
    fallback: str | None = None
    for header_name, prefix in RECIPIENT_HEADER_FAMILIES:
        raw_values = [v for n, v in message.raw_items() if n.lower() == header_name.lower()]
        if not raw_values:
            continue
        addresses: set[str] = set()
        for raw_value in raw_values:
            if not isinstance(raw_value, str) or "\r" in raw_value or CONTROL_PATTERN.search(raw_value):
                return f"{prefix}:ambiguous-or-invalid"
            unfolded = re.sub(r"\n[ \t]+", " ", raw_value)
            if "\n" in unfolded:
                return f"{prefix}:ambiguous-or-invalid"
            try:
                parsed = BytesParser(policy=policy.default).parsebytes(
                    b"To: " + unfolded.encode("utf-8", errors="strict") + b"\r\n\r\n")
            except (UnicodeError, ValueError):
                return f"{prefix}:ambiguous-or-invalid"
            field = parsed.get("To")
            if field is None or getattr(field, "defects", ()) or not getattr(field, "addresses", ()):
                return f"{prefix}:ambiguous-or-invalid"
            for address in field.addresses:
                if getattr(address, "defects", ()) or not isinstance(getattr(address, "addr_spec", None), str):
                    return f"{prefix}:ambiguous-or-invalid"
                addresses.add(address.addr_spec.casefold())
        mapped = {own[a] for a in addresses if a in own}
        if len(mapped) == 1:
            return f"{prefix}:{next(iter(mapped))}"
        if len(mapped) > 1:
            return f"{prefix}:ambiguous-or-invalid"
        # A provider often leaves its own mailbox in Delivered-To; keep it as a
        # fallback and let a later header name your address.
        fallback = f"{prefix}:other"
    return fallback or "missing"


def header_value(message: Message, name: str) -> str:
    """One header's text; never raises on a field the strict parser rejects."""
    try:
        value = message.get(name)
    except Exception:
        value = next((raw for key, raw in message.raw_items() if key.lower() == name.lower()), None)
    return "" if value is None else str(value)


def message_reference(key: str, message: Message | None) -> str:
    message_id = decode_value(header_value(message, "Message-ID")) if message is not None else ""
    return hashlib.sha256(f"{key}\n{message_id}".encode("utf-8", errors="replace")).hexdigest()


def thread_message_id(message: Message) -> str:
    """A single, unfolded, defect-free RFC Message-ID, or "" (no reply anchor)."""
    values = [v for n, v in message.raw_items() if n.lower() == "message-id"]
    if len(values) != 1:
        return ""
    try:
        parsed = message.get_all("Message-ID", [])
    except Exception:
        return ""
    if len(parsed) != 1 or getattr(parsed[0], "defects", ()):
        return ""
    value = values[0]
    if not isinstance(value, str) or len(value) > 998 or "\r" in value or "\n" in value:
        return ""
    return value if RFC_MESSAGE_ID.fullmatch(value) else ""


def _is_lookalike(domain: str, protected: Iterable[str]) -> bool:
    for own in protected:
        if domain == own or domain.endswith("." + own):
            continue
        if levenshtein(domain.replace("-", ""), own.replace("-", "")) <= LOOKALIKE_DISTANCE:
            return True
    return False


def _is_protected(domain: str, protected: Iterable[str]) -> bool:
    return any(domain == own or domain.endswith("." + own) for own in protected)


def screen(raw: bytes, cfg: Screening, *, mailbox_key: str = "") -> Verdict:
    """Classify one message.  Never raises on hostile input: a message that
    cannot be parsed comes back quarantined with no content."""
    try:
        verdict = _screen(raw, cfg, mailbox_key)
    except Exception:
        return withheld(mailbox_key or hashlib.sha256(raw).hexdigest(), "message_processing_failed")
    if len(raw) >= cfg.max_message_bytes:
        verdict = replace(verdict, disposition="quarantine", excerpt="",
                          reasons=tuple(sorted(set(verdict.reasons) | {"message_truncated"})))
    return verdict


def withheld(key: str, reason: str) -> Verdict:
    return Verdict(
        disposition="quarantine", reasons=(reason,), message_ref=message_reference(key, None),
        from_address="", from_domain="", reply_to_address="", subject="", date="", excerpt="",
        attachment_names=(), authentication=(), category="general", has_attachments=False,
        recipient="missing", thread_message_id="", owner_verified=False,
    )


def _screen(raw: bytes, cfg: Screening, mailbox_key: str) -> Verdict:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    key = mailbox_key or hashlib.sha256(raw).hexdigest()
    raw_from_name, raw_from_address = parseaddr(decode_value(header_value(message, "From")))
    raw_reply_name, raw_reply_address = parseaddr(decode_value(header_value(message, "Reply-To")))
    from_address = sanitize_display_text(raw_from_address, 254)
    reply_address = sanitize_display_text(raw_reply_address, 254)
    from_domain = safe_domain(from_address)
    reply_domain = safe_domain(reply_address)
    sender_domain_valid = bool(from_domain and DOMAIN_PATTERN.fullmatch(from_domain))
    raw_subject = normalize_text(decode_value(header_value(message, "Subject")), 300)
    body_for_classification, excerpt = body_texts(message, cfg.excerpt_chars)
    raw_names, suffixes = attachment_metadata(message)
    auth = auth_signals(message)
    combined = "\n".join((raw_from_name, raw_from_address, raw_reply_name, raw_reply_address,
                          raw_subject, body_for_classification, *raw_names))

    from_count = len([1 for n, _ in message.raw_items() if n.lower() == "from"])
    owner_verified = (
        from_count == 1
        and from_address.casefold() in cfg.owner_addresses
        and provider_dmarc_pass(message, from_domain, cfg.trusted_authserv_ids)
    )

    auth_failures = {item for item in auth if item.endswith("_fail")}
    dangerous = any(s in DANGEROUS_EXTENSIONS for s in suffixes)
    archive = any(s in ARCHIVE_EXTENSIONS for s in suffixes)
    injection = any(p.search(combined) for p in PROMPT_INJECTION_PATTERNS)
    credential = bool(CREDENTIAL_LURE.search(combined))
    code = bool(VERIFICATION_CODE_CONTEXT.search(combined) and VERIFICATION_CODE_VALUE.search(combined))
    account = bool(ACCOUNT_LURE.search(combined))
    payment = bool(PAYMENT_LURE.search(combined))
    risky = risky_urls(combined)
    reply_mismatch = bool(reply_domain and from_domain and reply_domain != from_domain)
    protected = bool(from_domain) and _is_protected(from_domain, cfg.protected_domains)
    protected_unverified = protected and not owner_verified
    lookalike = bool(from_domain) and _is_lookalike(from_domain, cfg.protected_domains)

    reasons: set[str] = set()
    if {"spf_fail", "dkim_fail", "dmarc_fail"} <= auth_failures:
        reasons.add("auth_triple_fail")
    elif auth_failures:
        reasons.add("auth_failure")
    for flag, on in (("dangerous_attachment", dangerous), ("archive_attachment", archive),
                     ("prompt_injection_pattern", injection), ("credential_lure", credential),
                     ("verification_code", code), ("account_lure", account), ("payment_lure", payment),
                     ("risky_url", risky), ("reply_to_mismatch", reply_mismatch),
                     ("protected_domain_unverified", protected_unverified),
                     ("protected_domain_lookalike", lookalike), ("malformed_sender", not sender_domain_valid)):
        if on:
            reasons.add(flag)
    if protected_unverified and auth_failures:
        reasons.add("protected_domain_auth_failure")

    lure = credential or account or payment
    # Trash needs three signals a reader can inspect in the message itself;
    # sender-written auth headers never authorize it.
    high_confidence = (dangerous and lure and risky and not auth_failures
                       and not protected_unverified and sender_domain_valid)
    ambiguous = (dangerous or injection or code or bool(auth_failures) or protected_unverified
                 or (lookalike and lure) or (risky and lure)
                 or (archive and (bool(auth_failures) or lure))
                 or (reply_mismatch and (bool(auth_failures) or lure))
                 or not sender_domain_valid)
    # Owner mail is held to the same content rules: a verified owner whose
    # message carries injection text or a dangerous file is still held.
    disposition = "trash" if high_confidence else "quarantine" if ambiguous else "clean"
    has_attachments = bool(raw_names)
    if payment:
        category = "payment_finance"
    elif credential or account or code:
        category = "account_security"
    elif has_attachments:
        category = "attachment_delivery"
    elif risky:
        category = "external_link"
    else:
        category = "general"
    clean = disposition == "clean"
    return Verdict(
        disposition=disposition,
        reasons=tuple(sorted(reasons)),
        message_ref=message_reference(key, message),
        from_address=from_address,  # already sanitized; decoding again could revive a link
        from_domain=from_domain,
        reply_to_address=(reply_address or from_address) if clean else "",
        subject=sanitize_display_text(raw_subject, 300) if clean else "",
        date=sanitize_display_text(decode_value(header_value(message, "Date")), 120) if clean else "",
        excerpt=excerpt if clean else "",
        attachment_names=tuple(sanitize_display_text(n, DISPLAY_CHARS) for n in raw_names) if clean else (),
        authentication=auth,
        category=category,
        has_attachments=has_attachments,
        recipient=recipient_observation(message, cfg.own_recipients),
        thread_message_id=thread_message_id(message) if clean else "",
        owner_verified=owner_verified,
    )
