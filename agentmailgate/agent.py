"""``amg-agent``: the only gateway commands an agent may run as the gateway user.

Give agents this program through sudo, never ``amg`` itself (README: Agent
access through sudo).  It accepts exactly

  amg-agent inbox
  amg-agent ack REF [REF ...]      REF = a 64-hex messageRef from inbox

and refuses every other argument list before it reads any file.  Each REF is
checked as its own argument, so sudo joining arguments with spaces cannot
smuggle an option or another command through.  The config is fixed: the
running user's ``~/.config/amg/gate.toml``, with the home directory taken from
the account database, not from the environment.
"""
from __future__ import annotations

import os
import pwd
import re
import sys
from pathlib import Path

from . import cli
from .vault import MAX_ROWS

REF = re.compile(r"[0-9a-f]{64}")
USAGE = "amg-agent: refused: use 'amg-agent inbox' or 'amg-agent ack REF [REF ...]' (REF = 64-hex messageRef)"


def config_path() -> Path:
    return Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".config" / "amg" / "gate.toml"


def gateway_argv(argv: list[str]) -> list[str] | None:
    """The validated subcommand for ``amg``, or None to refuse."""
    if argv == ["inbox"]:
        return ["inbox"]
    if len(argv) >= 2 and argv[0] == "ack" and len(argv) - 1 <= MAX_ROWS \
            and all(REF.fullmatch(ref) for ref in argv[1:]):
        return ["ack", *argv[1:]]
    return None


def main(argv: list[str] | None = None, config: Path | None = None) -> int:
    command = gateway_argv(sys.argv[1:] if argv is None else list(argv))
    if command is None:
        print(USAGE, file=sys.stderr)
        return 2
    return cli.main(["--config", str(config or config_path()), *command])


if __name__ == "__main__":
    raise SystemExit(main())
