"""Owner-approved replies to screened mail.

The reply goes only to the address the screened message itself named
(Reply-To, else From), in the same thread, with the subject fixed to
``Re: <original>``.  The owner approves the exact body bytes; the send is
claimed exclusively before SMTP, so one approval can produce at most one
message, and a crash between claim and outcome never re-sends.  A ``STOP``
file in the state directory refuses every reply, as it does every sequence send.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .approval import KIND_REPLY, Approvals, sha256
from .config import Config
from .transport import NotSent, Outbox, build_message, make_message_id
from .vault import Vault, VaultError, stop_requested, write_private


def expected_subject(original: str) -> str:
    subject = original or "Your message"
    return (subject if subject.lower().startswith("re:") else f"Re: {subject}")[:220]


def approve(cfg: Config, ref: str, body: bytes) -> dict[str, Any]:
    vault = Vault(cfg.state_dir)
    target = vault.reply_target(ref)
    text = body.decode("utf-8")
    if not text.strip():
        raise VaultError("empty reply body")
    if not target.get("threadMessageId"):
        raise VaultError("reply_thread_anchor_missing: the message had no valid Message-ID")
    body_path = vault.replies / f"{ref}.body"
    write_private(body_path, body)
    payload = {"to": target["replyTo"], "subject": expected_subject(target["subject"]),
               "bodySha256": sha256(body)}
    Approvals(cfg.state_dir).sign(KIND_REPLY, ref, payload)
    return payload


def send(cfg: Config, ref: str, outbox: Outbox) -> str:
    vault = Vault(cfg.state_dir)
    payload = Approvals(cfg.state_dir).load(KIND_REPLY, ref)
    target = vault.reply_target(ref)
    body = (vault.replies / f"{ref}.body").read_bytes()
    if sha256(body) != payload["bodySha256"]:
        raise VaultError("reply body changed after approval")
    if payload["to"].casefold() != target["replyTo"].casefold():
        raise VaultError("reply_recipient_mismatch")
    if payload["subject"] != expected_subject(target["subject"]):
        raise VaultError("reply_subject_mismatch")
    domain = cfg.sender.message_id_domain or cfg.sender.from_address.rpartition("@")[2]
    message = build_message(cfg, to=payload["to"], subject=payload["subject"], body=body.decode("utf-8"),
                            message_id=make_message_id(domain), anchors=[target["threadMessageId"]])
    if stop_requested(cfg.state_dir):
        raise VaultError("stopped: a STOP file is present; nothing was sent")
    claim: Path = vault.claim_reply(ref, sha256(bytes(message)))
    try:
        outcome = outbox.send(message, payload["to"])
    except NotSent:
        claim.unlink()  # certainly not sent: the approval may be used again
        raise
    vault.record_reply(ref, outcome)
    return outcome
