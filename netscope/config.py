"""Optional config file for per-user defaults.

Saves retyping the same flags on every run. A config only supplies *defaults*:
anything given on the command line wins.

Where it is read from:

* ``--config FILE`` (or the ``NETSCOPE_CONFIG`` environment variable) -- must
  exist; use this for a config checked into a project/CI repo.
* otherwise ``~/.netscope/config.json`` if present.

A config in the current directory is deliberately **not** picked up
automatically. Settings like ``ignore_file`` (silences findings) and ``webhook``
(sends alerts elsewhere) change what an audit reports and where data goes, so
merely running netscope inside an untrusted checkout must not be able to
reconfigure it.

Example::

    {
      "subnet": "192.168.1.0/24",
      "timing": 2,
      "db": "~/audits/home.db",
      "ignore_file": "~/audits/accepted.txt",
      "fail_on": "high",
      "webhook": "https://ntfy.sh/my-lan"
    }

Keys may be written ``fail_on`` or ``fail-on``. Unknown keys are an error (so a
typo can't silently leave a safety setting unapplied).
"""

import ipaddress
import json
import os

DEFAULT_PATH = os.path.join("~", ".netscope", "config.json")
ENV_VAR = "NETSCOPE_CONFIG"


class ConfigError(ValueError):
    """The config file is unreadable or has an invalid setting."""


def _string(key, value):
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"'{key}' must be a non-empty string")
    return value.strip()


def _subnet(key, value):
    value = _string(key, value)
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as e:
        raise ConfigError(f"'{key}': {e}") from None
    return value


def _timing(key, value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 5:
        raise ConfigError(f"'{key}' must be an integer from 0 to 5")
    return value


def _choice(*options):
    def check(key, value):
        if value not in options:
            raise ConfigError(f"'{key}' must be one of {', '.join(options)}")
        return value
    return check


def _path(key, value):
    return os.path.expanduser(_string(key, value))


def _url(key, value):
    value = _string(key, value)
    if not value.lower().startswith(("http://", "https://")):
        raise ConfigError(f"'{key}' must be an http:// or https:// URL")
    return value


def _ip(key, value):
    value = _string(key, value)
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise ConfigError(f"'{key}' must be an IP address") from None
    return value


# config key -> (argparse dest, validator)
SETTINGS = {
    "subnet": ("subnet", _subnet),
    "method": ("method", _choice("auto", "arp", "sweep")),
    "timing": ("timing", _timing),
    "db": ("db", _path),
    "ignore_file": ("ignore_file", _path),
    "fail_on": ("fail_on", _choice("critical", "high", "medium", "low")),
    "webhook": ("webhook", _url),
    "gateway": ("gateway", _ip),
    "iface": ("iface", _string),
}


def parse(data, source="config"):
    """Validate a decoded config document -> {argparse dest: value}."""
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: expected a JSON object of settings")
    out = {}
    for raw_key, value in data.items():
        key = str(raw_key).strip().lower().replace("-", "_")
        if key not in SETTINGS:
            raise ConfigError(f"{source}: unknown setting '{raw_key}' "
                              f"(known: {', '.join(sorted(SETTINGS))})")
        dest, check = SETTINGS[key]
        try:
            out[dest] = check(raw_key, value)
        except ConfigError as e:
            raise ConfigError(f"{source}: {e}") from None
    return out


def resolve_path(explicit=None, environ=None):
    """Return (path, required): --config beats $NETSCOPE_CONFIG beats the user file."""
    environ = os.environ if environ is None else environ
    if explicit:
        return os.path.expanduser(explicit), True
    if environ.get(ENV_VAR):
        return os.path.expanduser(environ[ENV_VAR]), True
    return (os.path.expanduser(DEFAULT_PATH) if DEFAULT_PATH else None), False


def load(explicit=None, environ=None):
    """Load and validate the config -> {argparse dest: value} ({} if none applies)."""
    path, required = resolve_path(explicit, environ)
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        if required:
            raise ConfigError(f"config file not found: {path}") from None
        return {}
    except (OSError, UnicodeError) as e:
        raise ConfigError(f"cannot read config file {path}: {e}") from None
    try:
        data = json.loads(text)
    except ValueError as e:
        raise ConfigError(f"{path}: invalid JSON: {e}") from None
    return parse(data, source=path)
