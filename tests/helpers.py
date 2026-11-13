import datetime as dt
import tempfile
from pathlib import Path

from agentmailgate.config import from_dict

ROOT = Path(__file__).resolve().parent.parent


def make_config(tmp: Path, **pace):
    return from_dict({
        "state_dir": str(tmp / "state"),
        "screening": {
            "protected_domains": ["example.com"],
            "own_recipients": {"hello@example.com": "hello"},
            "owner_addresses": ["owner@example.com"],
            "trusted_authserv_ids": ["mx.example.net"],
        },
        "sender": {"from_address": "hello@example.com", "from_name": "Example Co",
                   "reply_to": "hello@example.com", "message_id_domain": "example.com"},
        "pace": {"holidays": [], **pace},
    }, tmp)


class Clock:
    def __init__(self, start: dt.datetime):
        self.t = start

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += dt.timedelta(**kw)


class FakeOutbox:
    def __init__(self, outcome="accepted", exc=None):
        self.sent = []
        self.outcome = outcome
        self.exc = exc

    def send(self, message, to):
        if self.exc:
            raise self.exc
        self.sent.append((to, message))
        return self.outcome


def tempdir():
    return tempfile.TemporaryDirectory(prefix="amg-test-")
