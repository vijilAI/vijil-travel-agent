"""Dome SDK setup for Strands agents.

Usage — add to your Agent() constructor:

    from dome_setup import dome_hooks

    agent = Agent(
        ...
        hooks=dome_hooks,
    )
"""

from vijil_dome import Dome
from vijil_dome.integrations.strands import DomeHookProvider

dome = Dome("dome-config.toml")

dome_hooks = DomeHookProvider(dome)
