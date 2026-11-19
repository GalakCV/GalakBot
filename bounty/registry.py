"""Trusted install-time extensions; models cannot register executable plugins."""
from importlib.metadata import entry_points

from .core import Refused


class Registry:
    def __init__(self, group, defaults=None):
        self.items = dict(defaults or {})
        for entry in entry_points(group=group):
            self.register(entry.name, entry.load())

    def register(self, name, plugin):
        if name in self.items:
            raise Refused("Plugin name already registered: " + name)
        self.items[name] = plugin

    def get(self, name):
        if name not in self.items:
            raise Refused("Unknown plugin: " + name)
        return self.items[name]


class Captain:
    def plan(self, skill):
        return skill.plan()


class Triager:
    def review(self, observation):
        return {"state": "hypothesis", "rationale": "Independent verification required", "observation": observation}


def specialists():
    return Registry("bounty.specialists", {"captain": Captain, "triager": Triager})
