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

    def run(self, executor, *, authorized=False, host=None, client=None, phases=None, max_workers=4):
        import os
        if client is not None or os.environ.get("DEEPSEEK_API_KEY"):
            from .agents import AgentCampaign
            return AgentCampaign(executor.ctx, executor.skill, client=client, authorized=authorized,
                                 host=host, phases=phases, max_workers=max_workers).run()
        executor.ctx.config["engine"] = "deterministic"
        if phases and len(phases) == 1 and phases[0]["id"] == "http-probe" and executor.skill.name == "recon":
            return executor.thin_slice()
        return executor.campaign_run(phases or self.plan(executor.skill), authorized=authorized, host=host)


class Triager:
    def __init__(self, llm=None):
        self.llm = llm

    def review(self, observation, evidence=None, agent_id="triager"):
        if self.llm:
            from .agents import AgentTriager
            return AgentTriager(self.llm).review(observation, evidence or {}, agent_id)
        return {"state": "hypothesis", "rationale": "Independent verification required", "observation": observation}


def specialists():
    return Registry("bounty.specialists", {"captain": Captain, "triager": Triager})
