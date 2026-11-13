"""Encrypted, owner-only store for screened mail and one-shot reply claims.

Layout under ``state_dir`` (directories 0700, files 0600):

  vault.key           Fernet key (created on first use)
  vault.enc           encrypted JSON: {"messages": {ref: row}}
  replies/<ref>.json  exclusive-create claim written *before* SMTP; its
                      presence means "a reply to this message may have left"
  state.lock          flock for every mutation

Clean rows hold the bounded agent view plus the reply target and thread
anchor.  Quarantined rows hold metadata only: no address, subject or text.
"""
from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from cryptography.fernet import Fernet, InvalidToken

from .screen import Verdict

MAX_ROWS = 2_000


class VaultError(RuntimeError):
    pass


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not path.is_dir() or path.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise VaultError(f"{path} must be a real directory owned by this user with mode 0700")
    return path


def write_private(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    dir_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def write_exclusive(path: Path, value: dict[str, Any]) -> None:
    """Create ``path`` once; a second claim for the same thing fails."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise VaultError("already_claimed") from None
    try:
        os.write(fd, json.dumps(value, sort_keys=True).encode())
        os.fsync(fd)
    finally:
        os.close(fd)


class Vault:
    def __init__(self, state_dir: Path) -> None:
        self.root = private_dir(state_dir)
        self.key_path = self.root / "vault.key"
        self.data_path = self.root / "vault.enc"
        self.replies = private_dir(self.root / "replies")

    @contextmanager
    def lock(self) -> Iterator[None]:
        fd = os.open(self.root / "state.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _fernet(self) -> Fernet:
        if not self.key_path.exists():
            write_exclusive(self.key_path, {})  # reserve the name atomically
            write_private(self.key_path, Fernet.generate_key())
        info = self.key_path.lstat()
        if info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise VaultError("vault.key must be 0600 and owned by this user")
        return Fernet(self.key_path.read_bytes().strip())

    def load(self) -> dict[str, Any]:
        if not self.data_path.exists():
            return {"messages": {}}
        try:
            return json.loads(self._fernet().decrypt(self.data_path.read_bytes()))
        except InvalidToken:
            raise VaultError("vault.enc does not decrypt with vault.key") from None

    def save(self, value: dict[str, Any]) -> None:
        data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        write_private(self.data_path, self._fernet().encrypt(data))

    def add(self, verdict: Verdict) -> bool:
        """Store one screened message; returns False if it was already stored."""
        with self.lock():
            value = self.load()
            rows = value["messages"]
            if verdict.message_ref in rows:
                return False
            if len(rows) >= MAX_ROWS:
                raise VaultError("vault_full: acknowledge or prune before scanning more")
            row: dict[str, Any] = {"seenAt": now(), "status": "pending", **verdict.agent_view()}
            if verdict.disposition == "clean":
                row["private"] = {
                    "replyTo": verdict.reply_to_address,
                    "threadMessageId": verdict.thread_message_id,
                    "subject": verdict.subject,
                }
            rows[verdict.message_ref] = row
            self.save(value)
            return True

    def pending(self) -> list[dict[str, Any]]:
        rows = self.load()["messages"].values()
        return [{k: v for k, v in r.items() if k != "private"} for r in rows if r["status"] == "pending"]

    def acknowledge(self, refs: list[str]) -> int:
        with self.lock():
            value = self.load()
            count = 0
            for ref in refs:
                row = value["messages"].get(ref)
                if row and row["status"] == "pending":
                    row["status"] = "acknowledged"
                    count += 1
            self.save(value)
            return count

    def reply_target(self, ref: str) -> dict[str, str]:
        row = self.load()["messages"].get(ref)
        if not row:
            raise VaultError("unknown_message")
        if row["disposition"] != "clean" or "private" not in row:
            raise VaultError("message_withheld: no reply to quarantined mail")
        return dict(row["private"])

    def claim_reply(self, ref: str, payload_sha256: str) -> Path:
        path = self.replies / f"{ref}.json"
        write_exclusive(path, {"messageRef": ref, "payloadSha256": payload_sha256, "claimedAt": now()})
        return path

    def record_reply(self, ref: str, outcome: str) -> None:
        with self.lock():
            value = self.load()
            row = value["messages"].get(ref)
            if row:
                row["status"] = "replied" if outcome == "accepted" else f"reply_{outcome}"
            self.save(value)
