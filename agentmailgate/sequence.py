"""Zero-LLM sender for owner-approved sequences.

An agent writes a batch file: rows of recipient + exact messages.  The owner
approves the batch's sha256 (``amg sequence approve``).  From then on a timer
runs ``tick`` and no model is involved in any send.

One tick, in order:

1. ``STOP`` or ``stop-<sequenceId>`` in the state directory: send nothing.
2. Read new inbound headers (read-only POP).  Replies, auto-replies,
   opt-outs, bounces and complaints stop their rows; a complaint, a
   sender-block bounce, or bounces at or above the halt rate halt the batch.
   If the read fails, send nothing: stops must be seen before the next send.
3. Send at most one message, when: the window is open, the jittered gap since
   the last send has passed, the daily caps have room, the batch is approved,
   unhalted and inside its dates.  Follow-ups go in the same thread
   (``Re:`` subject, In-Reply-To/References).

Every send is claimed in an append-only, fsynced ledger *before* SMTP.  A claim
with no outcome is ``uncertain`` and that row is never sent again
automatically: a lost reply from the server must not become a duplicate.

A halt stays until the owner resumes it, naming every open halt.  A halt that
arrives after the owner read the batch makes the resume invalid, so the owner
never clears a halt they did not see.  A resumed batch sends follow-ups only.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import random
import re
from pathlib import Path
from typing import Any, Callable, Iterable

from . import stops
from .approval import KIND_SEQUENCE, Approvals, ApprovalError, canonical, sha256
from .config import ADDRESS, Config
from .transport import NotSent, Outbox, build_message, make_message_id
from .vault import private_dir, write_private

ROW_ID = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
SEQ_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,47}\Z")
MAX_ROWS = 50
MAX_STEPS = 3
MAX_FILE_BYTES = 256 * 1024
INBOUND_STOPS = frozenset({"replied", "auto_replied", "opted_out", "bounce", "complaint", "bounce_held"})
TERMINAL = frozenset({"replied", "auto_replied", "opted_out", "bounce", "complaint", "bounce_held",
                      "uncertain", "rejected", "failed", "completed"})

Inbound = Iterable[tuple[str, bytes, Callable[[], bytes]]]


class SequenceError(RuntimeError):
    pass


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(text: str) -> dt.datetime:
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


# ---------------------------------------------------------------- batch file

def validate_batch(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_FILE_BYTES:
        raise SequenceError("batch file too large")
    try:
        batch = json.loads(data)
    except ValueError:
        raise SequenceError("batch is not JSON") from None
    if not isinstance(batch, dict) or set(batch) != {"version", "sequenceId", "rows"} or batch["version"] != 1:
        raise SequenceError("batch keys must be exactly version (1), sequenceId, rows")
    if not isinstance(batch["sequenceId"], str) or not SEQ_ID.fullmatch(batch["sequenceId"]):
        raise SequenceError("sequenceId: lowercase letters, digits, hyphens; 1-48 chars")
    rows = batch["rows"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_ROWS:
        raise SequenceError(f"rows: 1 to {MAX_ROWS}")
    seen_ids, seen_to = set(), set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"id", "to", "steps"}:
            raise SequenceError("each row has exactly id, to, steps")
        if not isinstance(row["id"], str) or not ROW_ID.fullmatch(row["id"]) or row["id"] in seen_ids:
            raise SequenceError(f"row id invalid or repeated: {row.get('id')!r}")
        if not isinstance(row["to"], str) or not ADDRESS.fullmatch(row["to"]):
            raise SequenceError(f"row {row['id']}: to is not one plain address")
        key = stops.address_key(row["to"])
        if key in seen_to:
            raise SequenceError(f"row {row['id']}: recipient repeated in batch")
        seen_ids.add(row["id"])
        seen_to.add(key)
        steps = row["steps"]
        if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
            raise SequenceError(f"row {row['id']}: 1 to {MAX_STEPS} steps")
        for i, step in enumerate(steps):
            allowed = {"subject", "body"} if i == 0 else {"body"}
            if not isinstance(step, dict) or set(step) != allowed:
                raise SequenceError(f"row {row['id']} step {i + 1}: keys must be {sorted(allowed)}")
            if not all(isinstance(v, str) and v.strip() for v in step.values()):
                raise SequenceError(f"row {row['id']} step {i + 1}: empty text")
            if "{{" in "".join(step.values()):
                raise SequenceError(f"row {row['id']} step {i + 1}: unrendered placeholder")
    return batch


# ---------------------------------------------------------------- ledger

class Ledger:
    """Append-only JSONL; one fsync per event."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.events: list[dict[str, Any]] = []
        if path.exists():
            self.events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def append(self, event: dict[str, Any]) -> None:
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, canonical(event) + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        self.events.append(event)

    def rows(self) -> dict[str, dict[str, Any]]:
        state: dict[str, dict[str, Any]] = {}
        for event in self.events:
            row = event.get("rowId")
            if not row:
                continue
            entry = state.setdefault(row, {"sent": {}, "claims": {}, "status": "pending"})
            kind = event["event"]
            if kind == "claim":
                entry["claims"][event["step"]] = event
            elif kind == "sent":
                entry["sent"][event["step"]] = event
                entry["claims"].pop(event["step"], None)
            elif kind == "not_sent":
                entry["claims"].pop(event["step"], None)
            elif kind in ("rejected", "failed"):
                entry["claims"].pop(event["step"], None)
                entry["status"] = kind
            elif kind == "row_stop" and entry["status"] in ("pending", "active", "completed"):
                entry["status"] = event["reason"]
        for entry in state.values():
            if entry["claims"] and entry["status"] in ("pending", "active"):
                entry["status"] = "uncertain"
            elif entry["sent"] and entry["status"] == "pending":
                entry["status"] = "active"
        return state

    def open_halts(self) -> list[list[str]]:
        open_list: list[list[str]] = []
        for event in self.events:
            if event["event"] == "halt":
                open_list.append([event["at"], event["reason"]])
            elif event["event"] == "resume" and event.get("halts") == open_list:
                open_list = []
        return open_list

    def resumed(self) -> bool:
        return any(e["event"] == "resume" for e in self.events)

    def has(self, event: str, **match: Any) -> bool:
        return any(e["event"] == event and all(e.get(k) == v for k, v in match.items()) for e in self.events)


# ---------------------------------------------------------------- engine

class Engine:
    def __init__(self, cfg: Config, outbox: Outbox, *, now: Callable[[], dt.datetime] = utcnow,
                 rng: random.Random | None = None) -> None:
        self.cfg = cfg
        self.outbox = outbox
        self.now = now
        self.rng = rng or random.Random()
        self.root = private_dir(cfg.state_dir)
        self.seq_root = private_dir(self.root / "sequences")
        self.approvals = Approvals(cfg.state_dir)
        self.global_path = self.root / "sequence-global.json"

    # -- storage
    def _dir(self, seq: str) -> Path:
        return private_dir(self.seq_root / seq)

    def ledger(self, seq: str) -> Ledger:
        return Ledger(self._dir(seq) / "ledger.jsonl")

    def _global(self) -> dict[str, Any]:
        return json.loads(self.global_path.read_text()) if self.global_path.exists() else {"seenUidls": [], "nextSendAt": None}

    def _save_global(self, value: dict[str, Any]) -> None:
        value["seenUidls"] = value["seenUidls"][-5000:]
        write_private(self.global_path, canonical(value))

    def sequences(self) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
        """[(sequenceId, approval payload, batch)] for every signed approval."""
        out = []
        for path in sorted(self.seq_root.iterdir()):
            batch_path = path / "batch.json"
            if not batch_path.exists():
                continue
            try:
                approval = self.approvals.load(KIND_SEQUENCE, path.name)
            except ApprovalError:
                continue
            data = batch_path.read_bytes()
            if sha256(data) != approval["batchSha256"]:
                raise SequenceError(f"{path.name}: batch bytes changed after approval")
            out.append((path.name, approval, validate_batch(data)))
        return out

    # -- owner actions
    def approve(self, batch_bytes: bytes, *, not_before: dt.datetime, days: int) -> dict[str, Any]:
        batch = validate_batch(batch_bytes)
        seq = batch["sequenceId"]
        target = self._dir(seq) / "batch.json"
        if target.exists():
            raise SequenceError(f"sequence {seq} already exists; use a new sequenceId")
        write_private(target, batch_bytes)
        payload = {"batchSha256": sha256(batch_bytes), "rowCount": len(batch["rows"]),
                   "notBefore": iso(not_before), "stopAfter": iso(not_before + dt.timedelta(days=days))}
        self.approvals.sign(KIND_SEQUENCE, seq, payload)
        return payload

    def resume(self, seq: str, halts: list[list[str]]) -> None:
        """Owner resume: valid only if ``halts`` is exactly the open list now."""
        ledger = self.ledger(seq)
        if not ledger.open_halts():
            raise SequenceError("nothing to resume")
        if halts != ledger.open_halts():
            raise SequenceError("the open halts changed since you read them; read status again")
        self.approvals.sign(f"resume/{len(ledger.events)}", seq, {"halts": halts})
        ledger.append({"event": "resume", "at": iso(self.now()), "halts": halts, "scope": "followups_only"})

    # -- tick
    def stopped(self, seq: str | None = None) -> bool:
        return (self.root / "STOP").exists() or bool(seq and (self.root / f"stop-{seq}").exists())

    def tick(self, inbound: Callable[[set[str]], Inbound] | None) -> dict[str, Any]:
        if self.stopped():
            return {"result": "stopped", "why": "STOP file"}
        seqs = self.sequences()
        state = self._global()
        if inbound is not None and seqs:
            try:
                self._read_inbound(inbound, seqs, state)
            except Exception as exc:  # stops unseen -> no send
                return {"result": "no_send", "why": f"inbound_read_failed:{type(exc).__name__}"}
            self._save_global(state)
        elif seqs:
            return {"result": "no_send", "why": "no inbound reader: stops cannot be seen"}
        return self._send_one(seqs, state)

    def _read_inbound(self, inbound: Callable[[set[str]], Inbound], seqs, state) -> None:
        our_ids: dict[str, tuple[str, str]] = {}
        recipients: dict[str, list[tuple[str, str]]] = {}
        subjects: dict[str, list[tuple[str, str]]] = {}
        for seq, _approval, batch in seqs:
            ledger = self.ledger(seq)
            rows = ledger.rows()
            for row in batch["rows"]:
                if not rows.get(row["id"], {}).get("sent") and not rows.get(row["id"], {}).get("claims"):
                    continue
                recipients.setdefault(stops.address_key(row["to"]), []).append((seq, row["id"]))
                subjects.setdefault(stops.subject_key(row["steps"][0]["subject"]), []).append((seq, row["id"]))
            for e in ledger.events:
                if e["event"] in ("claim", "sent") and e.get("messageId"):
                    our_ids[e["messageId"]] = (seq, e["rowId"])
        own = frozenset(stops.address_key(a) for a in (self.cfg.sender.from_address, self.cfg.sender.reply_to) if a)
        seen = set(state["seenUidls"])
        for uidl, headers, fetch in inbound(seen):
            for kind, seq, row in stops.classify(headers, fetch, our_ids, recipients, own, subjects):
                self._apply(kind, seq, row, [s for s, _a, _b in seqs])
            state["seenUidls"].append(uidl)
        for seq, _approval, _batch in seqs:
            self._bounce_rate(seq)

    def _apply(self, kind: str, seq: str, row: str, all_seqs: list[str]) -> None:
        at = iso(self.now())
        if kind == "complaint_unmatched":
            for s in all_seqs:
                self.ledger(s).append({"event": "halt", "at": at, "reason": "complaint_unmatched"})
            return
        if kind.endswith("_unmatched") or not seq:
            return
        ledger = self.ledger(seq)
        if kind == "sender_block":
            ledger.append({"event": "halt", "at": at, "reason": "sender_block"})
            return
        if row and kind in INBOUND_STOPS:
            ledger.append({"event": "row_stop", "at": at, "rowId": row, "reason": kind})
        if kind == "complaint":
            ledger.append({"event": "halt", "at": at, "reason": "complaint"})

    def _bounce_rate(self, seq: str) -> None:
        ledger = self.ledger(seq)
        rows = ledger.rows()
        firsts = sum(1 for r in rows.values() if "1" in r["sent"] or 1 in r["sent"])
        bounces = sum(1 for r in rows.values() if r["status"] == "bounce")
        pace = self.cfg.pace
        if bounces >= pace.bounce_halt_min and firsts and bounces / firsts > pace.bounce_halt_rate:
            if not ledger.has("halt", reason=f"bounce_rate:{bounces}"):
                ledger.append({"event": "halt", "at": iso(self.now()), "reason": f"bounce_rate:{bounces}"})

    # -- pacing
    def window_open(self, now: dt.datetime) -> bool:
        p = self.cfg.pace
        if p.weekdays_only and now.weekday() >= 5:
            return False
        if now.date().isoformat() in p.holidays:
            return False
        return p.window_start_hour_utc <= now.hour < p.window_end_hour_utc

    def business_days_after(self, start: dt.datetime, count: int) -> dt.date:
        day = start.date()
        while count > 0:
            day += dt.timedelta(days=1)
            if (not self.cfg.pace.weekdays_only or day.weekday() < 5) and day.isoformat() not in self.cfg.pace.holidays:
                count -= 1
        return day

    def _sent_today(self, seqs, now: dt.datetime) -> tuple[int, int]:
        total = new = 0
        for seq, _a, _b in seqs:
            for e in self.ledger(seq).events:
                if e["event"] == "claim" and e["at"][:10] == now.date().isoformat():
                    total += 1
                    new += e["step"] == 1
        return total, new

    def _send_one(self, seqs, state) -> dict[str, Any]:
        now = self.now()
        if not seqs:
            return {"result": "idle", "why": "no approved sequences"}
        if not self.window_open(now):
            return {"result": "no_send", "why": "window_closed"}
        if state.get("nextSendAt") and now < parse_time(state["nextSendAt"]):
            return {"result": "no_send", "why": "gap"}
        total, new = self._sent_today(seqs, now)
        pace = self.cfg.pace
        if total >= pace.max_sends_per_day:
            return {"result": "no_send", "why": "daily_cap"}
        candidates = []  # (priority, seq, row, step)
        for seq, approval, batch in seqs:
            if self.stopped(seq) or now < parse_time(approval["notBefore"]) or now >= parse_time(approval["stopAfter"]):
                continue
            ledger = self.ledger(seq)
            if ledger.open_halts():
                continue
            rows = ledger.rows()
            for row in batch["rows"]:
                info = rows.get(row["id"], {"sent": {}, "claims": {}, "status": "pending"})
                if info["status"] in TERMINAL or info["claims"]:
                    continue
                sent = {int(k): v for k, v in info["sent"].items()}
                step = len(sent) + 1
                if step > len(row["steps"]):
                    continue
                if step == 1:
                    if ledger.resumed() or new >= pace.new_per_day:
                        continue
                    candidates.append((1, seq, row, step))
                else:
                    offsets = pace.followup_business_days
                    if step - 2 >= len(offsets):
                        continue
                    due = self.business_days_after(parse_time(sent[1]["at"]), offsets[step - 2])
                    if now.date() >= due:
                        candidates.append((0, seq, row, step))
        if not candidates:
            return {"result": "no_send", "why": "nothing_due"}
        candidates.sort(key=lambda c: (c[0], c[1], c[2]["id"], c[3]))
        _prio, seq, row, step = candidates[0]
        return self._send(seq, row, step, state, now)

    def _send(self, seq: str, row: dict[str, Any], step: int, state, now: dt.datetime) -> dict[str, Any]:
        ledger = self.ledger(seq)
        sent = {int(k): v for k, v in ledger.rows().get(row["id"], {"sent": {}})["sent"].items()}
        first_subject = row["steps"][0]["subject"]
        subject = first_subject if step == 1 else (first_subject if first_subject.lower().startswith("re:") else f"Re: {first_subject}")
        anchors = [sent[i]["messageId"] for i in sorted(sent)]
        domain = self.cfg.sender.message_id_domain or self.cfg.sender.from_address.rpartition("@")[2]
        message_id = make_message_id(domain)
        message = build_message(self.cfg, to=row["to"], subject=subject, body=row["steps"][step - 1]["body"],
                                message_id=message_id, anchors=anchors)
        base = {"rowId": row["id"], "step": step, "messageId": message_id}
        ledger.append({"event": "claim", "at": iso(now), **base})
        gap = self.rng.randint(self.cfg.pace.gap_min_s, self.cfg.pace.gap_max_s)
        state["nextSendAt"] = iso(now + dt.timedelta(seconds=gap))
        self._save_global(state)
        try:
            outcome = self.outbox.send(message, row["to"])
        except NotSent as exc:
            ledger.append({"event": "not_sent", "at": iso(self.now()), **base, "why": str(exc)})
            return {"result": "not_sent", "sequenceId": seq, "rowId": row["id"], "step": step}
        except Exception as exc:
            # The claim stays open: the row is uncertain and never retried.
            return {"result": "uncertain", "sequenceId": seq, "rowId": row["id"], "step": step,
                    "why": type(exc).__name__}
        event = "sent" if outcome == "accepted" else outcome
        ledger.append({"event": event, "at": iso(self.now()), **base})
        if event == "sent" and step == len(row["steps"]):
            ledger.append({"event": "row_stop", "at": iso(self.now()), "rowId": row["id"], "reason": "completed"})
        return {"result": event, "sequenceId": seq, "rowId": row["id"], "step": step}

    # -- reporting (no content, no addresses)
    def status(self) -> list[dict[str, Any]]:
        out = []
        for seq, approval, batch in self.sequences():
            ledger = self.ledger(seq)
            counts: dict[str, int] = {}
            rows = ledger.rows()
            for row in batch["rows"]:
                status = rows.get(row["id"], {}).get("status", "pending")
                counts[status] = counts.get(status, 0) + 1
            out.append({"sequenceId": seq, **approval, "rows": counts, "openHalts": ledger.open_halts(),
                        "followupsOnly": ledger.resumed(), "stopFile": self.stopped(seq)})
        return out
