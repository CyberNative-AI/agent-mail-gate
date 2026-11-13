"""``amg``: the command line.

Agent-safe commands (read screened data, propose):
  amg screen FILE.eml            classify one message, print the agent view
  amg inbox                      pending screened messages (agent view)
  amg ack REF [REF ...]          mark messages handled

Gateway commands (run by the gateway user or its timer):
  amg scan                       read new mail (read-only POP), screen, store
  amg ingest FILE.eml ...        screen and store mail delivered another way
  amg sequence tick              one send step of approved sequences
  amg reply send REF             send one approved reply

Owner commands (need owner.key):
  amg init
  amg reply approve REF --body-file reply.txt
  amg sequence approve batch.json --not-before 2026-12-01T14:00Z --days 21
  amg sequence status
  amg sequence resume SEQ --halts '<json list from status>'
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import tomllib
from pathlib import Path

from . import reply, screen
from .approval import ApprovalError, Approvals
from .config import ConfigError
from .config import Config, load
from .sequence import Engine, SequenceError, parse_time
from .transport import FileOutbox, PopReader, SmtpOutbox
from .vault import Vault, VaultError, private_dir, write_private


# These carry fixed text, row positions or ids that passed validation: never a
# supplied value, a path or mail content.  Other errors print a fixed code or
# their type only.
OWN_ERRORS = (ApprovalError, ConfigError, SequenceError, VaultError)
FILE_ERRORS = {FileNotFoundError: "file_not_found", tomllib.TOMLDecodeError: "config_not_toml"}


def _outbox(cfg: Config, args: argparse.Namespace):
    return FileOutbox(Path(args.outbox)) if args.outbox else SmtpOutbox(cfg)


def _print(value) -> None:
    json.dump(value, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


def cmd_screen(cfg: Config, args) -> int:
    raw = Path(args.file).read_bytes()
    _print(screen.screen(raw, cfg.screening).agent_view())
    return 0


def cmd_scan(cfg: Config, args) -> int:
    vault = Vault(cfg.state_dir)
    seen_path = cfg.state_dir / "scan-seen.json"
    seen = set(json.loads(seen_path.read_text())) if seen_path.exists() else set()
    counts = {"clean": 0, "quarantine": 0, "trash": 0}
    reader = PopReader(cfg, cfg.screening.max_message_bytes)
    for uidl, _headers, fetch in reader.messages(seen):
        verdict = screen.screen(fetch(), cfg.screening, mailbox_key=uidl)
        if vault.add(verdict):
            counts[verdict.disposition] += 1
        seen.add(uidl)
        write_private(seen_path, json.dumps(sorted(seen)).encode())
    _print({"stored": counts})
    return 0


def cmd_ingest(cfg: Config, args) -> int:
    """Screen and store .eml files delivered some other way (maildir, fetchmail, a test)."""
    vault = Vault(cfg.state_dir)
    stored = []
    for name in args.files:
        raw = Path(name).read_bytes()
        verdict = screen.screen(raw, cfg.screening)
        if vault.add(verdict):
            stored.append({"messageRef": verdict.message_ref, "disposition": verdict.disposition})
    _print(stored)
    return 0


def cmd_inbox(cfg: Config, args) -> int:
    _print(Vault(cfg.state_dir).pending())
    return 0


def cmd_ack(cfg: Config, args) -> int:
    _print({"acknowledged": Vault(cfg.state_dir).acknowledge(args.refs)})
    return 0


def cmd_init(cfg: Config, args) -> int:
    private_dir(cfg.state_dir)
    Approvals(cfg.state_dir).init_key()
    print(f"owner.key created in {cfg.state_dir}. Keep it out of every agent's reach.")
    return 0


def cmd_reply(cfg: Config, args) -> int:
    if args.action == "approve":
        _print(reply.approve(cfg, args.ref, Path(args.body_file).read_bytes()))
    else:
        _print({"outcome": reply.send(cfg, args.ref, _outbox(cfg, args))})
    return 0


def cmd_sequence(cfg: Config, args) -> int:
    engine = Engine(cfg, _outbox(cfg, args))
    if args.action == "approve":
        not_before = dt.datetime.now(dt.timezone.utc) if args.not_before == "now" else parse_time(args.not_before)
        _print(engine.approve(Path(args.batch).read_bytes(), not_before=not_before, days=args.days))
    elif args.action == "tick":
        reader = None if args.no_inbound else PopReader(cfg, 512 * 1024).messages
        if args.inbound_dir:
            reader = _dir_reader(Path(args.inbound_dir))
        _print(engine.tick(reader))
    elif args.action == "status":
        _print(engine.status())
    elif args.action == "resume":
        engine.resume(args.sequence, json.loads(args.halts))
        _print({"resumed": args.sequence, "scope": "followups_only"})
    return 0


def _dir_reader(directory: Path):
    """Inbound from a directory of .eml files (dry runs and tests)."""
    def read(seen: set[str]):
        for path in sorted(directory.glob("*.eml")):
            if path.name in seen:
                continue
            data = path.read_bytes()
            headers = re.split(rb"\r?\n\r?\n", data, maxsplit=1)[0] + b"\n\n"
            yield path.name, headers, (lambda d=data: d)
    return read


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="amg", description="Quarantining mail gateway for AI agents")
    parser.add_argument("--config", default="gate.toml")
    parser.add_argument("--outbox", help="write .eml files here instead of sending (dry run)")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("screen"); p.add_argument("file"); p.set_defaults(fn=cmd_screen)
    sub.add_parser("scan").set_defaults(fn=cmd_scan)
    p = sub.add_parser("ingest"); p.add_argument("files", nargs="+"); p.set_defaults(fn=cmd_ingest)
    sub.add_parser("inbox").set_defaults(fn=cmd_inbox)
    p = sub.add_parser("ack"); p.add_argument("refs", nargs="+"); p.set_defaults(fn=cmd_ack)
    sub.add_parser("init").set_defaults(fn=cmd_init)
    p = sub.add_parser("reply"); p.set_defaults(fn=cmd_reply)
    rs = p.add_subparsers(dest="action", required=True)
    a = rs.add_parser("approve"); a.add_argument("ref"); a.add_argument("--body-file", required=True)
    s = rs.add_parser("send"); s.add_argument("ref")
    p = sub.add_parser("sequence"); p.set_defaults(fn=cmd_sequence)
    ss = p.add_subparsers(dest="action", required=True)
    a = ss.add_parser("approve"); a.add_argument("batch"); a.add_argument("--not-before", required=True)
    a.add_argument("--days", type=int, default=21)
    t = ss.add_parser("tick"); t.add_argument("--inbound-dir"); t.add_argument("--no-inbound", action="store_true")
    ss.add_parser("status")
    r = ss.add_parser("resume"); r.add_argument("sequence"); r.add_argument("--halts", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(load(Path(args.config)), args)
    except OWN_ERRORS as exc:  # our own messages carry codes, never mail content
        print(f"amg: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    except tuple(FILE_ERRORS) as exc:  # the text would name the path or quote the file
        print(f"amg: {type(exc).__name__}: {FILE_ERRORS[type(exc)]}", file=sys.stderr)
        return 2
    except Exception as exc:  # anything else: the type only, no text that could quote mail
        print(f"amg: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
