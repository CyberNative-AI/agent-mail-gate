"""Mailbox access: read-only POP3 in, one text/plain message out.

The POP reader never deletes, moves or marks mail.  Outbound messages are a
single text/plain part with no attachments, CC, BCC or caller-supplied
headers.  ``FileOutbox`` writes .eml files instead of sending, for dry runs
and the quickstart.
"""
from __future__ import annotations

import email.policy
import poplib
import re
import secrets
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, formatdate
from pathlib import Path
from typing import Callable, Iterator, Protocol

from .config import ADDRESS, Config

HEADER_UNSAFE = re.compile(r"[\x00-\x1f\x7f]")
MAX_SUBJECT = 220
MAX_BODY_BYTES = 64 * 1024


class NotSent(Exception):
    """The message certainly did not leave (connect or login failed)."""


class Outbox(Protocol):
    def send(self, message: EmailMessage, to: str) -> str: ...


def make_message_id(domain: str) -> str:
    return f"<amg.{secrets.token_hex(12)}@{domain}>"


def build_message(cfg: Config, *, to: str, subject: str, body: str, message_id: str,
                  anchors: list[str] | None = None) -> EmailMessage:
    if not ADDRESS.fullmatch(to):
        raise ValueError("recipient is not one plain address")
    if HEADER_UNSAFE.search(subject) or len(subject) > MAX_SUBJECT:
        raise ValueError("subject has control characters or is too long")
    if len(body.encode()) > MAX_BODY_BYTES or "\x00" in body:
        raise ValueError("body too large or contains NUL")
    s = cfg.sender
    message = EmailMessage(policy=email.policy.SMTP.clone(max_line_length=998))
    message["From"] = formataddr((s.from_name, s.from_address)) if s.from_name else s.from_address
    if s.reply_to:
        message["Reply-To"] = s.reply_to
    message["To"] = to
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = message_id
    if anchors:
        message["In-Reply-To"] = anchors[-1]
        message["References"] = " ".join(anchors)
    message.set_content(body, subtype="plain", charset="utf-8", cte="quoted-printable")
    return message


def refusal_outcome(refused: dict) -> str:
    codes = [code for code, _msg in refused.values()] if refused else []
    if not codes:
        return "accepted"
    return "rejected" if all(500 <= int(c) < 600 for c in codes) else "failed"


class SmtpOutbox:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    def send(self, message: EmailMessage, to: str) -> str:
        user, password = self.cfg.mailbox.credentials()
        try:
            client = smtplib.SMTP_SSL(self.cfg.mailbox.smtp_host, self.cfg.mailbox.smtp_port,
                                      context=ssl.create_default_context(), timeout=30)
            client.login(user, password)
        except (OSError, smtplib.SMTPException) as exc:
            raise NotSent(type(exc).__name__) from None
        # From here on a failure is *uncertain*: the server may have accepted.
        with client:
            try:
                refused = client.send_message(message, to_addrs=[to])
            except smtplib.SMTPRecipientsRefused as exc:
                return refusal_outcome(exc.recipients)
        return refusal_outcome(refused)


class FileOutbox:
    """Writes each message to ``directory/<n>.eml``; returns "accepted"."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)

    def send(self, message: EmailMessage, to: str) -> str:
        n = len(list(self.directory.glob("*.eml"))) + 1
        (self.directory / f"{n:04d}.eml").write_bytes(bytes(message))
        return "accepted"


class PopReader:
    """Read-only POP3 session.  ``messages()`` yields (uidl, headers, fetch_full)."""

    def __init__(self, cfg: Config, max_bytes: int) -> None:
        self.cfg = cfg
        self.max_bytes = max_bytes

    def messages(self, seen: set[str]) -> Iterator[tuple[str, bytes, Callable[[], bytes]]]:
        user, password = self.cfg.mailbox.credentials()
        conn = poplib.POP3_SSL(self.cfg.mailbox.pop_host, self.cfg.mailbox.pop_port,
                               context=ssl.create_default_context(), timeout=60)
        try:
            conn.user(user)
            conn.pass_(password)
            _resp, listing, _ = conn.uidl()
            for line in listing:
                number, uidl = line.decode("ascii", "replace").split(" ", 1)
                if uidl in seen:
                    continue
                _resp, lines, _octets = conn.top(int(number), 0)
                headers = b"\r\n".join(lines) + b"\r\n\r\n"

                def fetch(number: int = int(number)) -> bytes:
                    _resp, body_lines, _octets = conn.retr(number)
                    data = b"\r\n".join(body_lines)
                    return data[: self.max_bytes]

                yield uidl, headers, fetch
        finally:
            # QUIT would commit deletions; we never mark any, but close without it
            # anyway so a bug elsewhere cannot turn into lost mail.
            try:
                conn.close()
            except Exception:
                pass
