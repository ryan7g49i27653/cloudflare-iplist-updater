"""Pure diff between desired networks and the managed items in the list."""

import logging
from dataclasses import dataclass, field

from . import untrusted
from .addresses import parse_network

log = logging.getLogger(__name__)


@dataclass
class Plan:
    to_add: list = field(default_factory=list)     # networks
    to_remove: list = field(default_factory=list)  # Cloudflare item dicts
    kept: list = field(default_factory=list)       # Cloudflare item dicts

    @property
    def changed(self):
        return bool(self.to_add or self.to_remove)


def is_managed(item, marker):
    comment = item.get("comment")
    return isinstance(comment, str) and marker in comment


def plan(desired, items, marker):
    """Compute changes.

    desired: {4: [networks] | None, 6: [networks] | None}. None means that
    family couldn't be determined this run, so its managed items are left
    untouched rather than removed. An empty list means the family is disabled
    and its managed items should go.
    items: every item in the Cloudflare list; unmanaged items are ignored.
    """
    result = Plan()
    seen = set()
    for item in items:
        if not is_managed(item, marker):
            continue
        try:
            net = parse_network(item.get("ip"))
        except ValueError as e:
            log.warning("ignoring managed item %s: %s", untrusted.describe(item.get("id"), 40), e)
            continue
        wanted = desired.get(net.version)
        if wanted is None or (net in wanted and net not in seen):
            result.kept.append(item)
            seen.add(net)
        else:
            result.to_remove.append(item)

    for version, wanted in desired.items():
        for net in wanted or []:
            if net not in seen:
                result.to_add.append(net)
                seen.add(net)
    return result
