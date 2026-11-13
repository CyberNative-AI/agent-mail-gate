"""Operator configuration, read from one TOML file.

Nothing about a particular company, mailbox or provider is built in.  Every
address, domain and host comes from the operator's file; credentials come
from environment variables the file names, never from the file itself.
"""
from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ADDRESS = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")
DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}\Z")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Screening:
    # Domains you own.  Mail claiming to come from them is held unless it is
    # verified owner mail; near-miss spellings are held as lookalikes.
    protected_domains: tuple[str, ...] = ()
    # Your inbound addresses mapped to short labels ("hello@x" -> "hello").
    # Only the label is ever recorded, never the address list.
    own_recipients: dict[str, str] = field(default_factory=dict)
    # People whose mail may carry instructions, and the authserv-id(s) of the
    # *receiving* provider whose Authentication-Results header you trust.
    owner_addresses: tuple[str, ...] = ()
    trusted_authserv_ids: tuple[str, ...] = ()
    max_message_bytes: int = 512_000
    excerpt_chars: int = 1_600


@dataclass(frozen=True)
class Mailbox:
    pop_host: str = ""
    pop_port: int = 995
    smtp_host: str = ""
    smtp_port: int = 465
    user_env: str = "AMG_MAIL_USER"
    password_env: str = "AMG_MAIL_PASSWORD"

    def credentials(self) -> tuple[str, str]:
        user = os.environ.get(self.user_env, "")
        password = os.environ.get(self.password_env, "")
        if not user or not password:
            raise ConfigError(f"set {self.user_env} and {self.password_env} in the gateway's environment")
        return user, password


@dataclass(frozen=True)
class Sender:
    from_address: str = ""
    from_name: str = ""
    reply_to: str = ""
    message_id_domain: str = ""


@dataclass(frozen=True)
class Pace:
    window_start_hour_utc: int = 13
    window_end_hour_utc: int = 21
    weekdays_only: bool = True
    holidays: tuple[str, ...] = ()  # "YYYY-MM-DD"
    gap_min_s: int = 120
    gap_max_s: int = 300
    new_per_day: int = 20
    max_sends_per_day: int = 80
    followup_business_days: tuple[int, ...] = (3, 7)
    bounce_halt_rate: float = 0.03
    bounce_halt_min: int = 2


@dataclass(frozen=True)
class Config:
    state_dir: Path
    screening: Screening
    mailbox: Mailbox
    sender: Sender
    pace: Pace


def _addresses(values: Any, name: str) -> tuple[str, ...]:
    out = []
    for value in values or ():
        if not isinstance(value, str) or not ADDRESS.fullmatch(value):
            raise ConfigError(f"{name}: not an address: {value!r}")
        out.append(value.casefold())
    return tuple(out)


def _domains(values: Any, name: str) -> tuple[str, ...]:
    out = []
    for value in values or ():
        if not isinstance(value, str) or not DOMAIN.fullmatch(value.lower()):
            raise ConfigError(f"{name}: not a domain: {value!r}")
        out.append(value.lower())
    return tuple(out)


def from_dict(data: dict[str, Any], base: Path) -> Config:
    s = data.get("screening", {})
    recipients = s.get("own_recipients", {}) or {}
    if not isinstance(recipients, dict):
        raise ConfigError("screening.own_recipients must be a table of address = label")
    own = {}
    for address, label in recipients.items():
        _addresses([address], "screening.own_recipients")
        if not isinstance(label, str) or not re.fullmatch(r"[a-z0-9_-]{1,32}", label):
            raise ConfigError(f"screening.own_recipients: bad label {label!r}")
        own[address.casefold()] = label
    screening = Screening(
        protected_domains=_domains(s.get("protected_domains"), "screening.protected_domains"),
        own_recipients=own,
        owner_addresses=_addresses(s.get("owner_addresses"), "screening.owner_addresses"),
        trusted_authserv_ids=tuple(str(v).casefold() for v in s.get("trusted_authserv_ids", ()) or ()),
        max_message_bytes=int(s.get("max_message_bytes", 512_000)),
        excerpt_chars=int(s.get("excerpt_chars", 1_600)),
    )
    if screening.owner_addresses and not screening.trusted_authserv_ids:
        raise ConfigError("screening.owner_addresses needs screening.trusted_authserv_ids (your provider's)")
    m = data.get("mailbox", {})
    mailbox = Mailbox(**{k: m[k] for k in Mailbox.__dataclass_fields__ if k in m})
    snd = data.get("sender", {})
    sender = Sender(**{k: snd[k] for k in Sender.__dataclass_fields__ if k in snd})
    for name in ("from_address", "reply_to"):
        value = getattr(sender, name)
        if value:
            _addresses([value], f"sender.{name}")
    p = data.get("pace", {})
    pace_args = {k: p[k] for k in Pace.__dataclass_fields__ if k in p}
    for key in ("holidays", "followup_business_days"):
        if key in pace_args:
            pace_args[key] = tuple(pace_args[key])
    pace = Pace(**pace_args)
    if not 0 <= pace.window_start_hour_utc < pace.window_end_hour_utc <= 24:
        raise ConfigError("pace: window hours must satisfy 0 <= start < end <= 24")
    state = Path(data.get("state_dir", "state"))
    if not state.is_absolute():
        state = (base / state).resolve()
    return Config(state_dir=state, screening=screening, mailbox=mailbox, sender=sender, pace=pace)


def load(path: Path) -> Config:
    with open(path, "rb") as handle:
        data = tomllib.load(handle)
    return from_dict(data, path.resolve().parent)
