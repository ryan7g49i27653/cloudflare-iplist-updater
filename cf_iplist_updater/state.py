"""Small JSON state file (last known addresses, cached IPv6 prefix length)."""

import json
import logging
import os
import tempfile

log = logging.getLogger(__name__)


def load(path):
    try:
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            log.warning("ignoring state file %s: not a JSON object", path)
            return {}
        return data
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        log.warning("ignoring unreadable state file %s: %s", path, e)
        return {}


def save(path, data):
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".state-")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise
