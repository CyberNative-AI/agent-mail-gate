"""Owner approvals: exact bytes, signed with a key agents cannot read.

An agent may *propose* a reply or a batch by writing a file.  Nothing is sent
until the owner runs ``approve``, which signs the sha256 of those exact bytes
with ``owner.key``.  The sender re-hashes the file at send time and refuses a
mismatch, so an agent that can edit the proposal after approval gains nothing.

Run the gateway as its own Unix user (or container) and keep ``owner.key``
readable only by that user and the owner.  If an agent can read the key, it
can approve its own mail: the threat model says so plainly.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any

from .vault import private_dir, write_exclusive, write_private

KIND_REPLY = "reply/v1"
KIND_SEQUENCE = "sequence/v1"


class ApprovalError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Approvals:
    def __init__(self, state_dir: Path) -> None:
        self.root = private_dir(state_dir / "approvals")
        self.key_path = state_dir / "owner.key"

    def init_key(self) -> None:
        if self.key_path.exists():
            raise ApprovalError("owner.key already exists")
        write_exclusive(self.key_path, {})
        write_private(self.key_path, secrets.token_hex(32).encode())

    def _key(self) -> bytes:
        if not self.key_path.exists():
            raise ApprovalError("no owner.key: run `amg init` as the owner")
        info = self.key_path.lstat()
        if info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise ApprovalError("owner.key must be 0600 and owned by the gateway user")
        return self.key_path.read_bytes().strip()

    def sign(self, kind: str, subject_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = {"kind": kind, "id": subject_id, "payload": payload}
        mac = hmac.new(self._key(), canonical(body), hashlib.sha256).hexdigest()
        record = {**body, "mac": mac}
        path = self.root / f"{kind.replace('/', '-')}-{subject_id}.json"
        write_exclusive(path, record)
        return record

    def load(self, kind: str, subject_id: str) -> dict[str, Any]:
        path = self.root / f"{kind.replace('/', '-')}-{subject_id}.json"
        if not path.exists():
            raise ApprovalError("not_approved")
        record = json.loads(path.read_bytes())
        body = {k: record.get(k) for k in ("kind", "id", "payload")}
        expected = hmac.new(self._key(), canonical(body), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(record.get("mac", ""))) or body["kind"] != kind or body["id"] != subject_id:
            raise ApprovalError("approval_signature_invalid")
        return body["payload"]
